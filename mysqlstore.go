package mysqlstore

import (
	"encoding/json"
	"database/sql"
	"time"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
)

// NewTokenStore create a token store instance with mysql db connection
func NewTokenStore(db *sql.DB) (store oauth2.TokenStore, err error) {
	store = &TokenStore{db: db}
	return
}

// TokenStore token storage based on sql.DB(database/sql)
type TokenStore struct {
	db *sql.DB
}

func checkErr(err error) {
	if err != nil {
		println("Panic from storage.")
		panic(err)
	}
}

// Create new token to db
func (ts *TokenStore) Create(info oauth2.TokenInfo) (err error) {
	jv, err := json.Marshal(info)
	println(string(jv))
	println((info.GetAccessCreateAt().Format("2006-01-02")))
	if err != nil {
		return
	}

	if code := info.GetCode(); code != "" {
		stmt, err := ts.db.Prepare("INSERT INTO user_oauth (user_id,client_id,scope,auth_code,code_created_at,code_expire,access_token,access_created_at,access_expire,refresh_token,refresh_created_at,refresh_expire,redirect_url)		 VALUE (?,?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE scope=?,auth_code=?,code_created_at=?,code_expire=?,redirect_url=?;")
		checkErr(err)
		_, err = stmt.Exec(
			info.GetUserID(),
			info.GetClientID(),
			info.GetScope(),
			info.GetCode(),
			info.GetCodeCreateAt().Format("2006-01-02 15:04:05"),
			info.GetCodeExpiresIn(),
			info.GetAccess(),
			info.GetAccessCreateAt().Format("2006-01-02 15:04:05"),
			info.GetAccessExpiresIn(),
			info.GetRefresh(),
			info.GetRefreshCreateAt().Format("2006-01-02 15:04:05"),
			info.GetRefreshExpiresIn(),
			info.GetRedirectURI(),
			info.GetScope(),
			info.GetCode(),
			info.GetCodeCreateAt().Format("2006-01-02 15:04:05"),
			info.GetCodeExpiresIn(),
			info.GetRedirectURI())
		checkErr(err)
		return err
	}

	aexp := info.GetAccessCreateAt().Add(info.GetAccessExpiresIn())
	rexp := aexp
	if refresh := info.GetRefresh(); refresh != "" {
		rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn())
		if aexp.Second() > rexp.Second() {
			aexp = rexp
		}
	}
	
	// Update access_token
	stmt, err := ts.db.Prepare("UPDATE user_oauth SET access_token = ?, access_expire = ? WHERE user_id = ? AND client_id = ?")
	checkErr(err)
	_, err = stmt.Exec(info.GetAccess(), aexp.Second(), info.GetUserID(),info.GetClientID())
	checkErr(err)

	if refresh := info.GetRefresh(); refresh != "" {
		// Update refresh
		stmt, err := ts.db.Prepare("UPDATE user_oauth SET refresh_token = ?, refresh_expire = ? WHERE user_id = ? AND client_id = ?")
		checkErr(err)
		_, err = stmt.Exec(refresh, rexp.Second(), info.GetUserID(),info.GetClientID())
		checkErr(err)
	}
	return
}

// remove key
func (ts *TokenStore) remove(key string) (err error) {
	stmt, err := ts.db.Prepare("UPDATE user_oauth SET access_token = ? WHERE access_token = ?")
	checkErr(err)
	// info
	_, err = stmt.Exec(key)
	checkErr(err)
	return err
}

// RemoveByCode use the authorization code to delete the authorization information
func (ts *TokenStore) RemoveByCode(code string) (err error) {
	stmt, err := ts.db.Prepare("UPDATE user_oauth SET auth_code = '' WHERE auth_code = ?")
	checkErr(err)
	// info
	_, err = stmt.Exec(code)
	checkErr(err)
	return err
}

// RemoveByAccess use the access token to delete the access token information
func (ts *TokenStore) RemoveByAccess(access string) (err error) {
	stmt, err := ts.db.Prepare("UPDATE user_oauth SET access_token = '' WHERE access_token = ?")
	checkErr(err)
	// info
	_, err = stmt.Exec(access)
	checkErr(err)
	return err
}

// RemoveByRefresh use the refresh token to delete the refresh token information
func (ts *TokenStore) RemoveByRefresh(refresh string) (err error) {
	stmt, err := ts.db.Prepare("UPDATE user_oauth SET refresh_token = '' WHERE refresh_token = ?")
	checkErr(err)
	// info
	_, err = stmt.Exec("",refresh)
	checkErr(err)
	return err
}


func (ts *TokenStore) getData(userID,clientID string) (ti oauth2.TokenInfo, err error) {
	// query
	// println("GETDATA : "+userID+"|"+clientID)
	rows, err := ts.db.Query("SELECT user_id,client_id,scope,auth_code,code_created_at,code_expire,access_token,access_created_at,access_expire,refresh_token,refresh_created_at,refresh_expire,redirect_url FROM user_oauth WHERE user_id = ? AND client_id = ?  limit 1",userID,clientID)
	checkErr(err)
	var tm = models.NewToken()
	var codeCreateAt string
	var codeExpire string
	var accessCreateAt string
	var accessExpire string
	var refreshCreateAt string
	var refreshExpire string
	for rows.Next() {
		err = rows.Scan( &tm.UserID, &tm.ClientID , &tm.Scope, &tm.Code, &codeCreateAt,&codeExpire, &tm.Access ,&accessCreateAt, &accessExpire , &tm.Refresh ,&refreshCreateAt, &refreshExpire,&tm.RedirectURI)
	}
	tCode,_ := time.Parse("2006-01-02 15:04:05", codeCreateAt)
	dCode,_ := time.ParseDuration(codeExpire)
	dAccess,_ := time.ParseDuration(accessExpire)
	tAccess,_ := time.Parse("2006-01-02 15:04:05", accessCreateAt)
	dRefresh,_ := time.ParseDuration(refreshExpire)
	tRefresh,_ := time.Parse("2006-01-02 15:04:05", refreshCreateAt)
	tm.CodeCreateAt = tCode
	tm.CodeExpiresIn = dCode
	tm.AccessCreateAt = tAccess
	tm.AccessExpiresIn = dAccess
	tm.RefreshCreateAt = tRefresh
	tm.RefreshExpiresIn= dRefresh
	ti = tm
	return
}

// GetByCode use the authorization code for token information data
func (ts *TokenStore) GetByCode(code string) (ti oauth2.TokenInfo, err error) {
 	rows, err := ts.db.Query("SELECT user_id,client_id FROM user_oauth WHERE auth_code = ?  limit 1",code)
	var userID,clientID string
	for rows.Next() {
		err = rows.Scan( &userID,&clientID)
		if err != nil {
			return
		}
	}
	ti, err = ts.getData(userID,clientID)
	return
}

// GetByAccess use the access token for token information data
func (ts *TokenStore) GetByAccess(access string) (ti oauth2.TokenInfo, err error) {
	rows, err := ts.db.Query("SELECT user_id,client_id FROM user_oauth WHERE access_token = ?  limit 1",access)
	var userID,clientID string
	for rows.Next() {
		err = rows.Scan( &userID,&clientID)
		if err != nil {
			return
		}
	}
	ti, err = ts.getData(userID,clientID)
	return
}

// GetByRefresh use the refresh token for token information data
func (ts *TokenStore) GetByRefresh(refresh string) (ti oauth2.TokenInfo, err error) {
	rows, err := ts.db.Query("SELECT access_token FROM user_oauth WHERE refresh_token = ?  limit 1",refresh)
	var userID,clientID string
	for rows.Next() {
		err = rows.Scan( &userID,&clientID)
		if err != nil {
			return
		}
	}
	ti, err = ts.getData(userID,clientID)
	return
}

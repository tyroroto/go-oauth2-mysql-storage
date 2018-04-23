# Mysql Storage for OAuth 2.0

> Based on the oauth2 token storage

## Install

``` bash
$ go get -u github.com/tyroroto/go-oauth2-mysql-storage
```

## Usage

``` go
exec oauth_sql.sql file to your mysql_db
package main

import (
	"github.com/tyroroto/go-oauth2-mysql-storage"
	"gopkg.in/oauth2.v3/manage"
)

func main() {
	// use mysql token store
	var err error
	db, err = sql.Open("mysql", "root:@tcp(localhost:3306)/[your_scheme]?charset=utf8")
	checkErr(err)
	defer db.Close()

	manager := manage.NewDefaultManager()
	// token store
	manager.MustTokenStorage(mysql_store.NewTokenStore(db))
	// ...
}
```

## MIT License

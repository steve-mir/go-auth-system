package sqlc

import (
	"database/sql"
	"log"
	"time"

	"github.com/steve-mir/go-auth-system/internal/utils"
)

func CreateDbPool(config utils.Config) (*sql.DB, error) {
	log.Println("CreateDbPool Initiated: ")
	db, err := sql.Open(config.DBDriver, config.DBSource)
	if err != nil {
		log.Fatal("Cannot connect to db:", err)
	}
	// defer db.Close()

	DB_MAX_IDLE_CONN := config.DBMaxIdleConn
	DB_MAX_OPEN_CONN := config.DBMaxOpenConn
	DB_MAX_IDLE_TIME := config.DBMaxIdleTime
	DB_MAX_LIFE_TIME := config.DBMaxLifeTime

	db.SetMaxIdleConns(DB_MAX_IDLE_CONN)
	db.SetMaxOpenConns(DB_MAX_OPEN_CONN)
	db.SetConnMaxIdleTime(time.Duration(DB_MAX_IDLE_TIME) * time.Second)
	db.SetConnMaxLifetime(time.Duration(DB_MAX_LIFE_TIME) * time.Second)

	log.Println("@CreateDbPool POSTGRES_SQL MAX Open Connections: ", db.Stats().MaxOpenConnections)

	// This is for analyzing the stats after setting a connection

	log.Println("@CreateDbPool MYSQL Open Connections: ", db.Stats().OpenConnections)
	log.Println("@CreateDbPool MYSQL InUse Connections: ", db.Stats().InUse)
	log.Println("@CreateDbPool MYSQL Idle Connections: ", db.Stats().Idle)

	if err != nil {
		log.Fatalln("CreateDbPool Error: ", err)
		return nil, err
	}

	return db, err
}

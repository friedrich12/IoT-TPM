/*
 * Copyright (C) 2021 Friedrich Doku
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"fmt"
	"log"
	"bufio"
	"os"
	"net"
	"time"
	"io/fs"
	"io/ioutil"
	"github.com/oracle/nosql-go-sdk/nosqldb"
	"github.com/oracle/nosql-go-sdk/nosqldb/types"
	"github.com/oracle/nosql-go-sdk/nosqldb/auth/iam"
)

type filestats struct {
	size          int64
	path	      string
	permissions   fs.FileMode
	modified      time.Time
}

const (
	CONN_HOST = ""
	CONN_PORT = "8080"
	CONN_TYPE = "tcp"
)

func check(e error){
	if e != nil {
		panic(e)
	}
}

func getFileStats(filename string) filestats{
	fileStat, err := os.Stat(filename)

	if err != nil {
		log.Fatal(err);
	}

	frez := filestats{fileStat.Size(), "", fileStat.Mode(), fileStat.ModTime()}
	return frez
}

func UploadToDatabase(fs filestats){

	provider, err := iam.NewSignatureProviderFromFile("/Users/fdoku/.oci/config", "", "", "fdoku")
	if err != nil {
		fmt.Printf("failed to create new SignatureProvider: %v\n", err)
	}
	cfg := nosqldb.Config{
		Region:                "us-phoenix-1",
		AuthorizationProvider: provider,
	}
	client, err := nosqldb.NewClient(cfg)
	if err != nil {
		fmt.Printf("failed to create a NoSQL client: %v\n", err)
	}else{
		fmt.Printf("Sucsessfully created a NoSQL client\n");
	}

	//{
	//    "photoid": "123",
	//     "size": 4096,
	//      "permissions": "-rw-r--r--",
	//      "path": "photo.jpg",
        //      "modify" : "2006-01-02T15:04:05.999999999" 
	//}

	val := map[string]interface{}{
		"photoid": "123",
		"size": fs.size,
		"permissions": fs.permissions.String(),
		"path": "photo.jpg",
		"modify": fs.modified,
	}

	putReq := &nosqldb.PutRequest{
		TableName: "PhotoDB",
		Value:     types.NewMapValue(val),
	}

	putRes, err := client.Put(putReq)
	if err != nil {
		fmt.Printf("failed to put single row: %v\n", err)
	}
	fmt.Printf("Put row: %v\nresult: %v\n", putReq.Value.Map(), putRes)

	defer client.Close()
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	log.Println("Client connected from", remoteAddr)

	buf := bufio.NewReader(conn)
	rez := ""

	for {
		data, err := buf.ReadString('\n')
		if err != nil{
			break
		}
		rez += string(data)
	}

	conn.Write([]byte("Photo received."))
	conn.Close()


	data := []byte(string(rez))
	{
	    err := ioutil.WriteFile("photore.jpg", data, 0644)
		check(err)
	}

	fs := getFileStats("photore.jpg")

	fmt.Println("Size:", fs.size)             // Length in bytes for regular files
	fmt.Println("Permissions:", fs.permissions)      // File mode bits
	fmt.Println("Last Modified:", fs.modified) // Last modification time

	go UploadToDatabase(fs);
}


func main(){
	l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go handleRequest(conn)
	}
}

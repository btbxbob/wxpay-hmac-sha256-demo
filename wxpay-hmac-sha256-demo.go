package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"sort"
	"strings"
)

var data map[string]string
var key = ""

func init() {
	data = map[string]string{
		"mch_id":     "",
		"appid":      "",
		"openid":     "",
		"code":       "",
		"grant_type": "",
		"scope":      "",
	}
}

func main() {
	CalculateSignature(data, key)
}

// CalculateSignature return sign string
func CalculateSignature(fields map[string]string, key string) (result string, err error) {

	var keyList []string
	for k := range fields {
		keyList = append(keyList, k)
	}
	sort.Strings(keyList)
	var toSignString string
	for _, v := range keyList {
		if v != "sign" && fields[v] != "" {
			toSignString = toSignString + v + "=" + fields[v] + "&"
		}
	}
	toSignString = toSignString + "key=" + key
	log.Printf("toSignString, %#v\n", toSignString)
	hasher := hmac.New(sha256.New, []byte(key))
	hasher.Write([]byte(toSignString))
	result = hex.EncodeToString(hasher.Sum(nil))
	result = strings.ToUpper(result)
	log.Printf("%s\n", result)
	return result, nil
}

#include "bcrypt/BCrypt.hpp"
#include <duthomhas/csprng.hpp>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/pem.h>
#include <uuid/uuid.h>
#include <sqlite3.h>
#include <ctime>
#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <stdlib.h>

using namespace CryptoPP;
using namespace std;

void logError(string error);
string encryptString(string toencrypt, RSA::PublicKey pubkey);
string decryptString(string encoded,RSA::PrivateKey privkey);

static int callback(void *outputPtr, int argc, char **argv, char **azColName){
	vector<string> *list = reinterpret_cast<vector<string>*>(outputPtr);
    int i = 0;
    while(i < argc){
    	if(argv[i] != NULL){
		    list->push_back(argv[i]);
    	}
	    i++;
    } //while(i < argc)
    return 0;
} //static int callback(void *outputPtr, int argc, char **argv, char **azColName)

//Will return to caller 0 for error, 1 for invalid input, encrypted msg if good
int main(){
    char buffer [ 2048 ] = { 0 } ;
    fread ( buffer, 2048, 1, stdin ) ;
    string encoded = buffer;
    
    AutoSeededRandomPool prng;
    RSA::PrivateKey privkey;
    FileSource privfile("rsa-priv-xxx.pem",true);
    PEM_Load(privfile,privkey);
    
    string plain = decryptString(encoded,privkey);
    int split = plain.find(",");
    string username = plain.substr(0,split);
    int split2 = plain.find(",",split+1);
    string password = plain.substr(split+1,(split2-split-1));
    string newpubkey = plain.substr(split2+1);
    
    if(username.length() > 32){
        printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",1);
        logError("Username too long");
        return 1;
    }
    if(password.length() < 8 || password.length() > 128){
        printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",1);
        logError("Password wrong length");
        return 1;
    }
    
    BCrypt bcrypt;
    sqlite3* db;
    char *zErrMsg = 0;
    int rc;
    vector<string> results;
    
    rc = sqlite3_open("users.db", &db);
    if( rc ){
        printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",0);
        string err = "Can't open database: ";// + sqlite3_errmsg(db);
        logError(err);
        sqlite3_close(db);
        return 0;
    };
    
    string sql = "CREATE TABLE IF NOT EXISTS users(uuid text, username text, password text, pubkey text);";
    char* sql_clean = sqlite3_mprintf(sql.c_str());
    
    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
    sqlite3_free(sql_clean);
    if( rc != SQLITE_OK ){
      //fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }
    
    char* usr_clean = sqlite3_mprintf(username.c_str());
	sql = "SELECT username FROM users where username='" + string(usr_clean) + "';";
    sql_clean = sqlite3_mprintf(sql.c_str());
    results.clear();
    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
    sqlite3_free(sql_clean);
    sqlite3_free(usr_clean);
	if( rc != SQLITE_OK ){
	    printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",0);
    	logError("SQL Error");
	    sqlite3_free(zErrMsg);
	    sqlite3_close(db);
	    return 0;
    }else{
        if (!results.empty()){
        	printf ( "Content-Type:text/plain\n\n" ) ;
            printf ("%u",1);
            return 1;
        }
    }
    
    RSA::PublicKey newpublickey;
    StringSource npubkey(newpubkey,true);
    PEM_Load(npubkey, newpublickey);
    
    bool result = newpublickey.Validate(prng, 2);
    if(!result){
        printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",1);
        logError("Failed to validate new public key");
        return 0;
    }
    
    string newuserpub;
    StringSink ss(newuserpub);
    PEM_Save(ss.Ref(), newpublickey);
    
    uuid_t uuidObj;
	uuid_generate(uuidObj);
	char uuid_str[37];      // ex. "1b4e28ba-2fa1-11d2-883f-0016d3cca427" + "\0"
	uuid_unparse_lower(uuidObj, uuid_str);
	string uuidnew = uuid_str;
	string hashpass = bcrypt.generateHash(uuidnew+password);
	
	usr_clean = sqlite3_mprintf(username.c_str());
    sql = "CREATE TABLE IF NOT EXISTS "+ string(usr_clean) +"Inbox(msgnum integer,time text, userFrom text, message text);";
    sql_clean = sqlite3_mprintf(sql.c_str());
    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
    sqlite3_free(sql_clean);
    sqlite3_free(usr_clean);
    if( rc != SQLITE_OK ){
        printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",0);
        logError("SQL Error");
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return 0;
    } //if( rc != SQLITE_OK )
	
	char* uuidnew_clean = sqlite3_mprintf(uuidnew.c_str());
	usr_clean = sqlite3_mprintf(username.c_str());
	char* hashpass_clean = sqlite3_mprintf(hashpass.c_str());
	char* pub_clean = sqlite3_mprintf(newuserpub.c_str());
	sql = "INSERT INTO users VALUES('"+ string(uuidnew_clean) +"','"+ string(usr_clean) +"','"+ string(hashpass_clean) +"','"+ string(pub_clean) +"');";
	sql_clean = sqlite3_mprintf(sql.c_str());
    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
    sqlite3_free(sql_clean);
    sqlite3_free(uuidnew_clean);
    sqlite3_free(usr_clean);
    sqlite3_free(hashpass_clean);
    sqlite3_free(pub_clean);
    if( rc != SQLITE_OK ){
        printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",0);
        logError("SQL Error");
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return 0;
    }
    printf ( "Content-Type:text/plain\n\n" ) ;
    printf ("%u",2);
    return 2;
}

void logError(string error){
    ofstream out("addUser_log.txt",ofstream::app);
    time_t now = time(0);
	string msgTime = ctime(&now);
    out << msgTime << error << "\n";
    out.close();
}

string encryptString(string toencrypt, RSA::PublicKey pubkey){
    AutoSeededRandomPool prng;
    RSAES_PKCS1v15_Encryptor enc(pubkey); //for compatibility with JSEncrypt, doesn't support OAEP decrypting
    string encrypted;
    unsigned int i=0;
	for(;(i+85)<=toencrypt.length();i+=85){
		string temp_toencrypt = toencrypt.substr(i,85);
		string temp_cipher,temp_b64cipher;
		StringSource ss4(temp_toencrypt, true,
	  	new PK_EncryptorFilter(prng, enc,
	    	new StringSink(temp_cipher)
	    )
	  ); //StringSource
        StringSource ss5(temp_cipher, true,
          new Base64Encoder(
            new StringSink(temp_b64cipher)
          )
        ); //StringSource
        //logError(temp_b64cipher);
        encrypted += temp_b64cipher.substr(0,temp_b64cipher.length()-1);
	} //for(;(i+85)<msgToSend.length();i+=85)
	if(i<toencrypt.length()){
		string temp_resp = toencrypt.substr(i,toencrypt.length());
		string temp_cipher,temp_b64cipher;
		StringSource ss1(temp_resp, true,
        	new PK_EncryptorFilter(prng, enc,
          	    new StringSink(temp_cipher)
          )
        ); //StringSource
        StringSource ss2(temp_cipher, true,
          new Base64Encoder(
            new StringSink(temp_b64cipher)
          )
        ); //StringSource
        encrypted += temp_b64cipher.substr(0,temp_b64cipher.length()-1);
	} //if(i<msgToSend.length())
	return encrypted;
}

string decryptString(string encoded, RSA::PrivateKey privkey){
    AutoSeededRandomPool prng;
    RSAES_PKCS1v15_Decryptor dec(privkey);
    string plain;
    unsigned int j = 0;
    for(;(j+172)<=encoded.length();j+=172){
		try{
			string temp_encoded = encoded.substr(j,172);
		    string temp_todecrypt,temp_plain;
  		    StringSource ss1(temp_encoded, true,
	            new Base64Decoder(
                    new StringSink(temp_todecrypt)
	            )
		    ); //StringSource
  		    StringSource ss2(temp_todecrypt, true,
	            new PK_DecryptorFilter(prng, dec,
                    new StringSink(temp_plain)
	            )
		    ); //StringSource
		    plain += temp_plain;
		    //logError(plain);
		} //try
		catch (...) {
		    logError("Decryption failed, check key");
			return "";
		} //catch(...)
	}// for(;(j+256)<encoded.length();j+=256)
	if(j < encoded.length()){
		try{
      		string temp_encoded = encoded.substr(j,encoded.length());
      		string temp_todecrypt,temp_plain;
      		StringSource ss1(temp_encoded, true,
    	        new Base64Decoder(
                    new StringSink(temp_todecrypt)
    	        )
    		); //StringSource
      		StringSource ss2(temp_todecrypt, true,
    	        new PK_DecryptorFilter(prng, dec,
    	        	new StringSink(temp_plain)
    	        )
		    ); //StringSource
		    plain += temp_plain;
		} //try
		catch (...){
			logError("Decryption failed in if, check key");
			return "";
		}
	} //if(j < encoded.length())
	return plain;
}
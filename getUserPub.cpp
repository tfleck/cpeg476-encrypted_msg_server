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
    
    char buffer [ 1024 ] = { 0 } ;
    fread ( buffer, 1024, 1, stdin ) ;
    string encoded = buffer;
    
    AutoSeededRandomPool prng;
    RSA::PrivateKey privkey;
    FileSource privfile("rsa-priv-xxx.pem",true);
    PEM_Load(privfile,privkey);
    
    string plain = decryptString(encoded,privkey);
    int split = plain.find(',');
    string token = plain.substr(0,split);
    string toUser = plain.substr(split+1);
    
    sqlite3* db;
    char *zErrMsg = 0;
    int rc;
    vector<string> results;
    string curr_time = to_string(time(0));
    string upubkey,reqpubkey;
    
    rc = sqlite3_open("users.db", &db);
    if( rc ){
        printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",0);
        string err = "Can't open database: ";// + sqlite3_errmsg(db);
        logError(err);
        sqlite3_close(db);
        return 0;
    };
    
    char* token_clean = sqlite3_mprintf(token.c_str());
    string sql = "SELECT timestamp,userpubkey FROM sessions where token='"+ string(token_clean) + "';";
    char* sql_clean = sqlite3_mprintf(sql.c_str());
    results.clear();
    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
    sqlite3_free(sql_clean);
    sqlite3_free(token_clean);
    if( rc != SQLITE_OK ){
        printf ( "Content-Type:text/plain\n\n" );
        printf ("%u",0);
        string err = "SQL Error: ";//+sqlite3_errmsg(db);
        logError(err);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return 0;
    } else {
        if(results.empty()){
            printf ( "Content-Type:text/plain\n\n" );
            printf ("%u",1);
            logError("token not found");
            sqlite3_free(zErrMsg);
            sqlite3_close(db);
            return 1;
        }
        else if((stoi(curr_time)-stoi(results[0])) > 600){
            char* token_clean = sqlite3_mprintf(token.c_str());
            string sql = "DELETE FROM sessions where token='"+ string(token_clean) + "';";
            char* sql_clean = sqlite3_mprintf(sql.c_str());
            results.clear();
            rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
            sqlite3_free(sql_clean);
            sqlite3_free(token_clean);
            if( rc != SQLITE_OK ){
                printf ( "Content-Type:text/plain\n\n" );
                printf ("%u",0);
                string err = "SQL Error: ";//+sqlite3_errmsg(db);
                logError(err);
                sqlite3_free(zErrMsg);
                sqlite3_close(db);
                return 0;
            }
            printf ( "Content-Type:text/plain\n\n" );
            printf ("%u",1);
            logError("token is expired");
            sqlite3_free(zErrMsg);
            sqlite3_close(db);
            return 1;
        }
        else{
            upubkey = results[1];
        }
    }
    
    char* toUser_clean = sqlite3_mprintf(toUser.c_str());
    sql = "SELECT pubkey FROM users where username='"+ string(toUser_clean) + "';";
    sql_clean = sqlite3_mprintf(sql.c_str());
    results.clear();
    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
    sqlite3_free(sql_clean);
    sqlite3_free(toUser_clean);
    if( rc != SQLITE_OK ){
        printf ( "Content-Type:text/plain\n\n" );
        printf ("%u",0);
        string err = "SQL Error: ";//+sqlite3_errmsg(db);
        logError(err);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return 0;
    } else {
        if(!results.empty()){
            reqpubkey = results[0];
        }
        else{
            printf ( "Content-Type:text/plain\n\n" ) ;
            printf ("%u",1);
            logError("Couldn't get user's public key");
            return 0;
        }
    }
    
    RSA::PublicKey userpubkey;
    StringSource pubkeystring(upubkey,true);
    PEM_Load(pubkeystring, userpubkey);
    
    bool result = userpubkey.Validate(prng, 2);
    if(!result){
        printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",0);
        logError("Failed to validate user's public key");
        return 0;
    }
    
    RSA::PublicKey requserpubkey;
    StringSource pubkeystring2(reqpubkey,true);
    PEM_Load(pubkeystring2, requserpubkey);
    
    result = requserpubkey.Validate(prng, 2);
    if(!result){
        printf ( "Content-Type:text/plain\n\n" ) ;
        printf ("%u",0);
        logError("Failed to validate requested user's public key");
        return 0;
    }
    
    string resp_encoded = encryptString(reqpubkey,userpubkey);
    printf ( "Content-Type:text/plain\n\n" ) ;
    printf ("%s",resp_encoded.c_str());
    return 2;
}

void logError(string error){
    ofstream out("getUserPub_log.txt",ofstream::app);
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
			logError("plain: "+plain);
			return "";
		}
	} //if(j < encoded.length())
	return plain;
}
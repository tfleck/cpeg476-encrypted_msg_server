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
    
    string token = decryptString(encoded,privkey);
    logError("removing token: "+token);
    
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
    else{
        logError("token removed");
        printf ( "Content-Type:text/plain\n\n" );
        printf ("%u",2); 
        return 2;
    }
}

void logError(string error){
    ofstream out("logoutUser_log.txt",ofstream::app);
    time_t now = time(0);
	string msgTime = ctime(&now);
    out << msgTime << error << "\n";
    out.close();
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
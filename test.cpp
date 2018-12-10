#include "bcrypt/BCrypt.hpp"
#include <uuid/uuid.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/pem.h>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

std::string& ltrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");
std::string& rtrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");
std::string& trim(std::string& str, const std::string& chars = "\t\n\v\f\r ");
int getch();
void getpass(const char *prompt, char* pwd, int pwdlen, bool show_asterisk=true);
void clearChar(char* arr, int arrlen);
void clearUChar(unsigned char* arr, int arrlen);
int mainMenu();
int validateLogin(sqlite3* db, string usrname, char* usrpwd, int usrpwdlen);
int printInbox(sqlite3* db, string usrname, char* usrkey, int usrkeylen);
int sendMessage(sqlite3* db, string username);

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

int main(){
	  srand (time(NULL));
	  AutoSeededRandomPool rng;
	  BCrypt bcrypt;
		sqlite3* db;
    char *zErrMsg = 0;
    int rc;
    vector<string> results;
    string sql,name,uuid,hash_password;
    int maxpwdlen = 128;
    int maxprivlen = 1300;
    string userallowedchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    rc = sqlite3_open("users.db", &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    };
    results.clear();
    sql = "CREATE TABLE IF NOT EXISTS users(uuid text, username text, password text, pubkey text);";
    char* sql_clean = sqlite3_mprintf(sql.c_str());
    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
    sqlite3_free(sql_clean);
    if( rc != SQLITE_OK ){
      //fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }
    
    string resp;
    cout << "Would you like to create a user? (y/n)" << endl;
    getline(cin,resp);
    trim(resp);
    while((resp.length() != 1) || (resp.find_first_not_of("yn") != string::npos)){
	    cout << "Would you like to create a user? (y/n)" << endl;
	    getline(cin,resp);
	    trim(resp);
    }
    if(resp.compare("y") == 0){
    	string usr,pass;
    	bool valid = false;
    	while(!valid){
	    	cout << "User name (<32 Characters, only alphanumeric): " << endl;
	    	getline(cin, usr);
	    	trim(usr);
	    	if(usr.length() > 32 || (usr.find_first_not_of(userallowedchars) != string::npos)){
	    		cout << "Username invalid or taken, please try again" << endl;
	    	}else{
	    		results.clear();
	    		char* usr_clean = sqlite3_mprintf(usr.c_str());
		    	sql = "SELECT username FROM users where username='" + string(usr_clean) + "';";
				  char* sql_clean = sqlite3_mprintf(sql.c_str());
			    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
			    sqlite3_free(sql_clean);
			    sqlite3_free(usr_clean);
				  if( rc != SQLITE_OK ){
				  fprintf(stderr, "SQL error: %s\n", zErrMsg);
				    sqlite3_free(zErrMsg);
				    sqlite3_close(db);
				    return 0;
				  }else{
				    if (!results.empty()){
				    	cout << "Username invalid or taken, please try again" << endl;
				    }
				    else{
				    	valid = true;
				    }
				  }
	    	}
    	}
    	valid = false;
    	while(!valid){
    		cout << "Password (8-128 characters): " <<endl;
    		getline(cin, pass);
    		trim(pass);
    		if(pass.length() > 128){
    			cout << "Password exceeds length maximum" << endl;
    		}
    		else if(pass.length() < 8){
    			cout << "Please choose a stronger password" << endl;
    		}
    		else{
    			valid = true;
    		}
    	}
    	uuid_t uuidObj;
			uuid_generate(uuidObj);
			char uuid_str[37];      // ex. "1b4e28ba-2fa1-11d2-883f-0016d3cca427" + "\0"
			uuid_unparse_lower(uuidObj, uuid_str);
			string uuidnew = uuid_str;
			string pub;
			unsigned char priv[maxprivlen];
			clearUChar(priv,maxprivlen);
			RSA::PrivateKey privkey;
	    privkey.GenerateRandomWithKeySize(rng, 1024);
	    RSA::PublicKey pubkey(privkey);
	    //ArraySink as(priv,maxprivlen);
	    //StringSink ss(priv);
	    //PEM_Save(as.Ref(), privkey);
	    //StringSink ss2(pub);
    	//PEM_Save(ss2.Ref(), pubkey);
    	
			HexEncoder pubkeysink(new StringSink(pub));
			pubkey.DEREncode(pubkeysink);
			pubkeysink.MessageEnd();
			
			HexEncoder privkeysink(new ArraySink(priv,maxprivlen));
			privkey.DEREncode(privkeysink);
			privkeysink.MessageEnd();
			
	    cout << "Private Key - SAVE IN A SAFE PLACE" << endl;
	    cout << priv << endl;
	    clearUChar(priv,maxprivlen);
    	string hashpass = bcrypt.generateHash(uuidnew+pass);
    	pass.erase(); //not the most secure, couldn't find better alternative without causing other problems
    	results.clear();
    	char* uuidnew_clean = sqlite3_mprintf(uuidnew.c_str());
    	char* usr_clean = sqlite3_mprintf(usr.c_str());
    	char* hashpass_clean = sqlite3_mprintf(hashpass.c_str());
    	char* pub_clean = sqlite3_mprintf(pub.c_str());
    	sql = "INSERT INTO users VALUES('"+ string(uuidnew_clean) +"','"+ string(usr_clean) +"','"+ string(hashpass_clean) +"','"+ string(pub_clean) +"');";
    	char* sql_clean = sqlite3_mprintf(sql.c_str());
	    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
	    sqlite3_free(sql_clean);
	    sqlite3_free(uuidnew_clean);
	    sqlite3_free(usr_clean);
	    sqlite3_free(hashpass_clean);
	    sqlite3_free(pub_clean);
	    if( rc != SQLITE_OK ){
	      fprintf(stderr, "SQL error: %s\n", zErrMsg);
	      sqlite3_free(zErrMsg);
	      sqlite3_close(db);
	      return 1;
	    }
	    results.clear();
	    usr_clean = sqlite3_mprintf(usr.c_str());
	    sql = "CREATE TABLE IF NOT EXISTS "+ string(usr_clean) +"Inbox(msgnum integer,time text, userFrom text, message text);";
	    sql_clean = sqlite3_mprintf(sql.c_str());
	    rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
	    sqlite3_free(usr_clean);
	    sqlite3_free(sql_clean);
	    if( rc != SQLITE_OK ){
	      //fprintf(stderr, "SQL error: %s\n", zErrMsg);
	      sqlite3_free(zErrMsg);
	    }
    }
    int e = -1;
    int tries = 0;
    cout << "Welcome to Cyberdyne!" << endl;
    while((e != 2) && (tries < 3)){
	    cout << "What is your username?"<< endl;
		  getline(cin,name);
		  trim(name);
		  if(name.length() > 32 || (name.find_first_not_of(userallowedchars) != string::npos)){
		  	cout << "Username invalid" << endl;
		  }
		  else{
			  string prompt = "Thank you "+ name +".  What is your password?";
			  char pwd[maxpwdlen];
			  clearChar(pwd,maxpwdlen);
	  		getpass(prompt.c_str(),pwd,maxpwdlen);
			  e = validateLogin(db,name,pwd,maxpwdlen);
			  if(e == 0){
			  	return 0;
			  }
			  tries++;
		  }
    }
    if(e != 2 && tries >= 3){
    	cout << "Sorry, please try again later" << endl;
    	sqlite3_close(db);
    	return 0;
    }
    
    
    int m = -1;
    while(m != 4){
    	m = mainMenu();
    	if(m == 1){
    		results.clear();
    		sql = "SELECT username FROM users";
    		char* sql_clean = sqlite3_mprintf(sql.c_str());
    		sql = string(sql_clean);
		    rc = sqlite3_exec(db, sql.c_str(), callback, &results, &zErrMsg);
		    sqlite3_free(sql_clean);
		    if( rc != SQLITE_OK ){
		    fprintf(stderr, "SQL error: %s\n", zErrMsg);
		      sqlite3_free(zErrMsg);
		      sqlite3_close(db);
		      return 1;
		    }else{
		      if (!results.empty()){
		      	unsigned int i = 0;
		      	cout << "Cyberdyne User Directory" << endl;
		      	for(;i<results.size();i++){
		      		cout << results[i] << endl;
		      	}
		      }
		    }
    	}
	    if(m == 2){
	    	int e = -1;
		    int tries = 0;
		    while((e != 2) && (tries < 3)){
				  string prompt = "What is your private key?";
				  char privkey[maxprivlen];
				  clearChar(privkey,maxprivlen);
		  		getpass(prompt.c_str(),privkey,maxprivlen);
				  e = printInbox(db,name,privkey,maxprivlen);
				  if(e == 0){
				  	return 0;
				  }
				  tries++;
		    }
		    if(e != 2 && tries >= 3){
		    	cout << "Sorry, please try again later" << endl;
		    	return 0;
		    }
	    } //if(m == 2)
	    if(m == 3){
	    	int e = sendMessage(db,name);
	    	if(e == 0){
	    		return 0;
	    	}
	    } //if(m == 3)
    } //while(m != 4)
  sqlite3_free(zErrMsg);
  sqlite3_close(db);
  cout << "Goodbye" << endl;
	return 0;
} //int main()

std::string& ltrim(std::string& str, const std::string& chars){
    str.erase(0, str.find_first_not_of(chars));
    return str;
} //std::string& ltrim(std::string& str, const std::string& chars)
 
std::string& rtrim(std::string& str, const std::string& chars){
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
} //std::string& rtrim(std::string& str, const std::string& chars)
 
std::string& trim(std::string& str, const std::string& chars){
    return ltrim(rtrim(str, chars), chars);
} //std::string& trim(std::string& str, const std::string& chars)

int getch(){
    int ch;
    struct termios t_old, t_new;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);
    return ch;
} //int getch() 

void getpass(const char *prompt, char* pwd, int pwdlen, bool show_asterisk){
	const char BACKSPACE=127;
	const char RETURN=10;
	unsigned char ch=0;
	int i = 0;

  cout <<prompt<<endl;
  while(((ch=getch())!=RETURN)){
		if(ch==BACKSPACE){
			if(i != 0){
        if(show_asterisk){
		      cout <<"\b \b";
        }
	      i--;
	      pwd[i] = 0;
			} //if(i != 0)
    }else{ //if(ch==BACKSPACE)
    	pwd[i] = ch;
      i++;
      if(show_asterisk){
       cout <<'*';
      }
    } //else
		if(i >= (pwdlen-1)){
			break;
		}
  } //while(((ch=getch())!=RETURN))
  pwd[i] = '\0';
  cout <<endl;
} //void getpass(const char *prompt, char* pwd, int pwdlen, bool show_asterisk=true)

void clearChar(char* arr, int arrlen){
	fill(arr,arr+arrlen,0);
}

void clearUChar(unsigned char* arr, int arrlen){
	fill(arr,arr+arrlen,0);
}


int mainMenu(){
	cout << "Main Menu" << endl;
  cout << "1. List All Users" << endl;
  cout << "2. View Messages" << endl;
  cout << "3. Send Message" << endl;
  cout << "4. Logoff System" << endl;
  string in;
  while((in.length() != 1) || (in.find_first_not_of("1234") != string::npos)){
  	cout << "Enter a number (1-4): " << endl;
  	getline(cin,in);
  	trim(in);
  } //while(in.length() != 1)
  return stoi(in);
} //int mainMenu()

int validateLogin(sqlite3* db, string usrname, char* usrpwd, int usrpwdlen){
	BCrypt bcrypt;
	char *zErrMsg = 0;
  int rc;
	vector<string> results;
	string sql,uuid;
  results.clear();
  char* usrname_clean = sqlite3_mprintf(usrname.c_str());
  sql = "SELECT uuid FROM users WHERE username='" + string(usrname_clean) + "';";
  char* sql_clean = sqlite3_mprintf(sql.c_str());
  rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
  sqlite3_free(sql_clean);
  sqlite3_free(usrname_clean);
  if( rc != SQLITE_OK ){
  fprintf(stderr, "SQL error: %s\n", zErrMsg);
    clearChar(usrpwd, usrpwdlen);
    sqlite3_free(zErrMsg);
    sqlite3_close(db);
    return 0;
  }else{
  	if (!results.empty()){
  		uuid = results[0];
  	}
  }
  results.clear();
  usrname_clean = sqlite3_mprintf(usrname.c_str());
  sql = "SELECT password FROM users where username='" + string(usrname_clean) + "';";
  sql_clean = sqlite3_mprintf(sql.c_str());
  rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
  sqlite3_free(sql_clean);
  sqlite3_free(usrname_clean);
  if( rc != SQLITE_OK ){
  fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
    sqlite3_close(db);
    clearChar(usrpwd, usrpwdlen);
    return 0;
  }else{
    if (!results.empty()){
    		if(bcrypt.validatePassword(uuid+usrpwd,results[0])){
    			clearChar(usrpwd, usrpwdlen);
      		cout << "You are logged in to the Cyberdyne secure message server " << usrname << "!" << endl;
      		return 2;
    		}else{
    			clearChar(usrpwd, usrpwdlen);
    			cout << "Invalid username or password" << endl;
    			return 1;
    		}
    		
    } else {
    	clearChar(usrpwd, usrpwdlen);
      cout << "Invalid username or password" << endl;
      return 1;
    }
  }
  clearChar(usrpwd, usrpwdlen);
  return 1;
}

int printInbox(sqlite3* db, string usrname, char* usrkey, int usrkeylen){
	AutoSeededRandomPool rng;
	char *zErrMsg = 0;
  int rc;
	vector<string> results;
	string sql;
	RSA::PrivateKey privkey;
  //cout << "Enter Private Key: " << endl;
	//getline(cin,privatekey);
	try{
		privkey.BERDecode(StringSource(usrkey,true,new HexDecoder()).Ref());
		//PEM_Load(StringSource(usrkey,true).Ref(), privkey);
		clearChar(usrkey, usrkeylen);
		if(!(privkey.Validate(rng,3))){
			cout << "Invalid key, please try again" << endl;
			return 1;
		}
	} //try
	catch (...){
		cout << "Invalid Key, Please try again" << endl;
		return 1;
	} //catch(...)
  RSAES_PKCS1v15_Decryptor dec(privkey);
  results.clear();
  cout << usrname << "'s Inbox" << endl;
  char* usrname_clean = sqlite3_mprintf(usrname.c_str());
	sql = "SELECT * FROM "+ string(usrname_clean) +"Inbox;";
	char* sql_clean = sqlite3_mprintf(sql.c_str());
  rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
  sqlite3_free(sql_clean);
  sqlite3_free(usrname_clean);
  if( rc != SQLITE_OK ){
  	fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
    sqlite3_close(db);
    return 0;
  }else{ //if( rc != SQLITE_OK )
    if (!results.empty()){
    	unsigned int i = 0;
    	for(;(i+3)<results.size();i+=4){
    		string encoded = results[i+3];
    		string plain;
    		unsigned int j = 0;
    		for(;(j+175)<encoded.length();j+=175){
    			try{
    				string temp_encoded = encoded.substr(j,175);
    			  string temp_todecrypt,temp_plain;
	      		StringSource ss1(temp_encoded, true,
			        new Base64Decoder(
		            new StringSink(temp_todecrypt)
			        )
				    ); //StringSource
	      		StringSource ss2(temp_todecrypt, true,
			        new PK_DecryptorFilter(rng, dec,
		            new StringSink(temp_plain)
			        )
				    ); //StringSource
				    plain += temp_plain;
    			} //try
    			catch (...) {
    				cout << "Inbox decryption failed, check key" << endl;
    				return 1;
    			} //catch(...)
    		}
    		if(j < encoded.length()){
    			try{
      			string temp_encoded = encoded.substr(j,encoded.length()-j);
      			string temp_todecrypt,temp_plain;
	      		StringSource ss1(temp_encoded, true,
			        new Base64Decoder(
		            new StringSink(temp_todecrypt)
			        )
				    ); //StringSource
	      		StringSource ss2(temp_todecrypt, true,
			        new PK_DecryptorFilter(rng, dec,
			        	new StringSink(temp_plain)
			        )
				    ); //StringSource
				    plain += temp_plain;
    			} //try
    			catch (...){
    				cout << "Inbox decryption failed, check key" << endl;
    				return 1;
    			}
    		} //if(j < encoded.length())
    		cout << "On: " << results[i+1] << " From: " << results[i+2] << " Msg: " << plain <<  endl;
    	} //for(;(i+2)<results.size();i+=3)
    } //if (!results.empty())
    else{
    	cout << "Inbox empty" << endl;
    }
  } //else
  return 2;
} //int printInbox(sqlite3* db, string usrname)

int sendMessage(sqlite3* db, string username){
	AutoSeededRandomPool rng;
	char *zErrMsg = 0;
  int rc;
	vector<string> results;
	string sql,toUser;
	cout << "Send to which user: " << endl;
	getline(cin, toUser);
	trim(toUser);
  string msgToSend,publickey,cipher,hexcipher;
	cout << "Message: " << endl;
	getline(cin, msgToSend);
	trim(msgToSend);
	
	time_t now  = time(0);
  struct tm *ltime = localtime(&now);
  int hour = ltime->tm_hour;
  if(hour < 5){
      hour = 24-(5-hour);
  }else{
      hour -= 5;
  }
  ltime->tm_hour = hour;
  string msgTime = asctime(ltime);
	string msgNum;
    
  char* toUser_clean = sqlite3_mprintf(toUser.c_str());
  sql = "SELECT MAX(msgnum) from "+ string(toUser_clean) +"Inbox;";
  char* sql_clean = sqlite3_mprintf(sql.c_str());
  results.clear();
  rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
  sqlite3_free(sql_clean);
  sqlite3_free(toUser_clean);
  if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
    sqlite3_close(db);
    return 0;
  } else {
      if(!results.empty()){
          msgNum = to_string(stoi(results[0])+1);
      }
      else{
          msgNum = "1";
      }
  }
	
	results.clear();
	toUser_clean = sqlite3_mprintf(toUser.c_str());
	sql = "SELECT pubkey FROM users WHERE username='"+ string(toUser_clean) +"';";
	sql_clean = sqlite3_mprintf(sql.c_str());
  rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
  sqlite3_free(sql_clean);
  sqlite3_free(toUser_clean);
  if( rc != SQLITE_OK ){
  fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
    sqlite3_close(db);
    return 0;
  }else{ //if( rc != SQLITE_OK )
  	publickey = results[0];
  }
  RSA::PublicKey pubkey;
  pubkey.BERDecode(StringSource(publickey,true,new HexDecoder).Ref());
  //PEM_Load(StringSource(publickey,true).Ref(),pubkey);
	RSAES_PKCS1v15_Encryptor enc(pubkey);
	unsigned int i=0;
	for(;(i+85)<msgToSend.length();i+=85){
		string temp_msgToSend = msgToSend.substr(i,85);
		string temp_cipher,temp_hexcipher;
		StringSource ss1(temp_msgToSend, true,
	  	new PK_EncryptorFilter(rng, enc,
	    	new StringSink(temp_cipher)
	    )
	  ); //StringSource
    StringSource ss2(temp_cipher, true,
      new Base64Encoder(
        new StringSink(temp_hexcipher)
      )
    ); //StringSource
    hexcipher += temp_hexcipher;
	} //for(;(i+85)<msgToSend.length();i+=85)
	if(i<msgToSend.length()){
		string temp_msgToSend = msgToSend.substr(i,msgToSend.length()-i);
		string temp_cipher,temp_hexcipher;
		StringSource ss1(temp_msgToSend, true,
    	new PK_EncryptorFilter(rng, enc,
      	new StringSink(temp_cipher)
      )
    ); //StringSource
    StringSource ss2(temp_cipher, true,
      new Base64Encoder(
        new StringSink(temp_hexcipher)
      )
    ); //StringSource
    hexcipher += temp_hexcipher;
	} //if(i<msgToSend.length())
  results.clear();
  toUser_clean = sqlite3_mprintf(toUser.c_str());
  char* msgNum_clean = sqlite3_mprintf(msgNum.c_str());
  char* msgTime_clean = sqlite3_mprintf(msgTime.c_str());
  char* username_clean = sqlite3_mprintf(username.c_str());
  char* hexcipher_clean = sqlite3_mprintf(hexcipher.c_str());
	sql = "INSERT INTO "+ string(toUser_clean) +"Inbox VALUES('"+ string(msgNum_clean) +"','"+ string(msgTime_clean) +"','"+ string(username_clean) +"','"+ string(hexcipher_clean) +"');";
  sql_clean = sqlite3_mprintf(sql.c_str());
  rc = sqlite3_exec(db, sql_clean, callback, &results, &zErrMsg);
  sqlite3_free(sql_clean);
  sqlite3_free(toUser_clean);
  sqlite3_free(msgTime_clean);
  sqlite3_free(hexcipher_clean);
  if( rc != SQLITE_OK ){
  	fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
    sqlite3_close(db);
    return 0;
  } //if( rc != SQLITE_OK )
  return 1;
} //int sendMessage(sqlite3* db)
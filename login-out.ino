#include <Wire.h>
#include <PN532_I2C.h>
#include <PN532.h>
#include <EEPROM.h>
#include <Keyboard.h>

PN532_I2C pn532i2c(Wire);
PN532 nfc(pn532i2c);

#define NR_SHORTSECTOR          (32)    // Number of short sectors on Mifare 1K/4K
#define NR_LONGSECTOR           (8)     // Number of long sectors on Mifare 4K
#define NR_BLOCK_OF_SHORTSECTOR (4)     // Number of blocks in a short sector
#define NR_BLOCK_OF_LONGSECTOR  (16)    // Number of blocks in a long sector

#define BLOCK_NUMBER_OF_SECTOR_TRAILER(sector) (((sector)<NR_SHORTSECTOR)? \
  ((sector)*NR_BLOCK_OF_SHORTSECTOR + NR_BLOCK_OF_SHORTSECTOR-1):\
  (NR_SHORTSECTOR*NR_BLOCK_OF_SHORTSECTOR + (sector-NR_SHORTSECTOR)*NR_BLOCK_OF_LONGSECTOR + NR_BLOCK_OF_LONGSECTOR-1))

#define BLOCK_NUMBER_OF_SECTOR_1ST_BLOCK(sector) (((sector)<NR_SHORTSECTOR)? \
  ((sector)*NR_BLOCK_OF_SHORTSECTOR):\
  (NR_SHORTSECTOR*NR_BLOCK_OF_SHORTSECTOR + (sector-NR_SHORTSECTOR)*NR_BLOCK_OF_LONGSECTOR))


struct LoginParams {
  char uid[15];
  char sysname[33];
  char platform;
  char sectorpasswd[7];
};

//#define DEBUG;

const uint8_t defaultKeyA[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const uint8_t defaultKeyB[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

uint8_t blankAccessBits[3] = { 0xff, 0x07, 0x80 };

void setup() {
  Serial.begin(9600);
  #ifdef DEBUG
    while(!Serial);
  #endif
  Serial.println(F("Start control..."));
  nfc.begin();
  
  #ifdef DEBUG
    uint32_t versiondata = nfc.getFirmwareVersion();
    if (! versiondata) {
      Serial.print(F("Didn't find PN53x board"));
      while (1); // halt
    }
    // Got ok data, print it out!
    Serial.print(F("Found chip PN5")); Serial.println((versiondata>>24) & 0xFF, HEX); 
    Serial.print(F("Firmware ver. ")); Serial.print((versiondata>>16) & 0xFF, DEC); 
    Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);
  #endif
  nfc.SAMConfig(); // configure board to read RFID tags  
  Keyboard.begin();
} 

String request_line;
bool cardSetupMode = false;
// "w:0:system_name:w:a1b2c3d4:sectorpwd"
// "a::system_name:g:d78ec561:sectorpwd"
void loop() {

  doLogInOut();

  while (Serial.available()) {
    char request_char = Serial.read();
    #ifdef DEBUG
      Serial.print(request_char);
    #endif
    if (request_char == '\n') {
      #ifdef DEBUG
        Serial.println("Incoming message...");
      #endif
      String action = getValue(request_line,':',0);
      
      if (action == "r") {
        eepromRead();
      } else if (action == "w") {
        String targetIdx = getValue(request_line,':',1);
        eepromWrite(targetIdx,false);
      } else if (action == "d") {
        eepromDelete();
      } else if (action == "a") {
        eepromAppend();
      } else if (action == "l") {
        eepromList();
      } else if (action == "count") {
        getEEPROMCount();
      } else if (action == "cr") {
        cardRead();
      } else if (action == "cw") {
        cardWrite();
      } else if (action == "ce") {
        cardErase();
      } else if (action == "setup") {
        setupModeSwitch();
      } else if (action == "dump") {
        dumpMemory();
      }
      
      request_line = "";
    } else {
      request_line.concat(request_char);
    } 
  }
}


void doLogInOut() {
  uint8_t success;
  String ringUid;
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0};  // Buffer to store the returned UID
  uint8_t uidLength; // Length of the UID (4 or 7 bytes depending on ISO14443A card type
  if (!cardSetupMode) {
    success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, &uid[0], &uidLength);
    if (success) {
      ringUid = charArrayToHex(uid,uidLength);
      LoginParams params;
      int idx = getCardInfoFromEEPROM(ringUid, params);
      if (idx > -1) {
        Serial.print(F("{\"function\":\"LogInOut\",\"action\":\"Card detected\",\"idx\":\""));
        Serial.print(idx);
        Serial.print(F("\",\"uid\":\""));
        Serial.print(ringUid);
        Serial.println(F("\"}"));

        uint8_t key[6];
        for(uint8_t i = 0; i<6; i++) {
          key[i] = uint8_t(params.sectorpasswd[i]);
        }
        #ifdef DEBUG
          Serial.print(F("LogInOut: sector password: "));
          nfc.PrintHexChar(key, 6);
        #endif
        success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, key);
        if (!success) {
          #ifdef DEBUG
            Serial.println("LogInOut: keyA Sector passwd not authenticate. Try defaultKeyB");
            Serial.print(F("LogInOut: defaultKeyB: "));
            nfc.PrintHexChar(defaultKeyB, 6);
          #endif
          nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength); //WORKAROUND
          success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, defaultKeyB);
        }
        if (success) {
          uint8_t data[16];
          success = nfc.mifareclassic_ReadDataBlock(4, data);
          if (success) {
            String passwdString = "";
            for(uint8_t i = 0; i < 16; i++) {
              if (data[i] == 0)
                break;
              passwdString.concat(char(data[i]));                
            }
            sendKeys(params, passwdString);
          } else {
            Serial.println(F("{\"function\":\"LogInOut\",\"result\":\"false\",\"details\":\"Card read error\"}"));
            delay(1000);
          }
        } else {
          Serial.println(F("{\"function\":\"LogInOut\",\"result\":\"false\",\"details\":\"Authentication error at card read\"}"));
          delay(1000);
        }        
      } else {
        Serial.print(F("{\"function\":\"LogInOut\",\"result\":\"false\",\"details\":\"Card not registered\",\"uid\":\""));
        Serial.print(ringUid);
        Serial.println(F("\"}"));
        delay(3000);
      }

    }
  }
}

void setupModeSwitch() {
  cardSetupMode = !cardSetupMode;
  Serial.print(F("{\"action\":\"setup\",\"mode\":\""));
  Serial.print(cardSetupMode ? "card" : "off");
  Serial.println(F("\"}"));
}

void eepromRead() {
  String targetIdx = getValue(request_line,':',1);
  uint8_t count;
  EEPROM.get(0,count);
  if ((targetIdx.toInt() >= count) || (targetIdx.toInt() < 0)) {
    Serial.print(F("{\"action\":\"eeprom-read\",\"result\":\"Index out of bounds\"}"));
    return;
  }
  int eeAddress = targetIdx.toInt() * sizeof(LoginParams) + 1;
  #ifdef DEBUG
    Serial.print(F("idx:"));
    Serial.println(targetIdx);
  #endif        
  LoginParams params;
  EEPROM.get(eeAddress, params);
  Serial.print(F("{\"sysname\":\""));
  Serial.print(params.sysname);
  Serial.print(F("\",\"platform\":\""));
  Serial.print(params.platform);
  Serial.print(F("\",\"uid\":\""));
  Serial.print(params.uid);
  Serial.print(F("\""));
  #ifdef DEBUG
    Serial.print(F(",\"sectorpassword\":\""));
    Serial.print(params.sectorpasswd);
    Serial.print(F("\""));
  #endif
  Serial.println(F("}"));
}

void eepromWrite(String targetIdx, boolean setEmptyPasswd) {
  uint8_t count;
  EEPROM.get(0,count);
  if ((targetIdx.toInt() >= count) || (targetIdx.toInt() < 0)) {
    Serial.println(F("Index out of bounds"));
    return;
  }
  int eeAddress = targetIdx.toInt() * sizeof(LoginParams) + 1;
  #ifdef DEBUG
    Serial.print(F("idx:"));
    Serial.println(targetIdx);
  #endif
  LoginParams params;
  String targetSysName = getValue(request_line,':',2);
  String targetPlatform = getValue(request_line,':',3);
  String targetNFCUID = getValue(request_line,':',4);
  String targetSectorPasswd = getValue(request_line,':',5);
  targetSysName.toCharArray(params.sysname, 33);
  targetNFCUID.toCharArray(params.uid, 15);
  
  if (targetPlatform.length()>0) {
    params.platform = targetPlatform[0];
  }
  if (targetSectorPasswd.length()>0) {
    targetSectorPasswd.toCharArray(params.sectorpasswd, 7);
  } else if (setEmptyPasswd) {
    for(uint8_t i = 0; i < 7; i++) {
      params.sectorpasswd[i] = (defaultKeyB[i]);
    }
  } else {
    LoginParams oldParams;
    if (getCardInfoFromEEPROM(targetNFCUID, oldParams) > -1) {
      for(uint8_t i = 0; i < 7; i++) {
        params.sectorpasswd[i] = (oldParams.sectorpasswd[i]);
      }
    }
    
  }
  
  #ifdef DEBUG
    Serial.print(F("targetSysName:"));
    Serial.println(targetSysName);
    Serial.print(F("targetPlatform:"));
    Serial.println(targetPlatform);
    Serial.print(F("targetNFCUID:"));
    Serial.println(targetNFCUID);
    Serial.print(F("targetSectorPasswd:"));
    Serial.println(targetSectorPasswd);
    Serial.print(F("Sysname["));
    Serial.print(sizeof(params.sysname));
    Serial.print(F(","));
    Serial.print(targetSysName.length());
    Serial.print(F("]:"));
    Serial.println(params.sysname);
    Serial.print(F("platform:"));
    Serial.println(params.platform);
    Serial.print(F("UID:"));
    Serial.println(params.uid);
    Serial.print(F("SectorPassword:"));
    if (targetSectorPasswd.length()>0) {
      Serial.println(params.sectorpasswd);
    } else {
      nfc.PrintHexChar(params.sectorpasswd,6);
    }
  #endif
  EEPROM.put(eeAddress, params);
  Serial.println(F("{\"action\":\"eeprom-write\",\"result\":\"done\"}"));
}

void eepromDelete() {
  uint8_t count;
  EEPROM.get(0,count);
  String targetIdx = getValue(request_line,':',1);
  LoginParams params;
  if ((targetIdx.toInt() == count-1) || (count == 1)) {
    EEPROM.put(0, uint8_t(count-1));  
  } else if ((targetIdx.toInt() >= count) || (targetIdx.toInt() < 0)) {
    Serial.print(F("{\"action\":\"eeprom-write\",\"result\":\"Index out of bounds\"}"));
    return;
  } else if (targetIdx.toInt() < count-1) {
      int eeAddress = targetIdx.toInt() * sizeof(LoginParams) + 1;
      int lastAddress = (count -1) * sizeof(LoginParams) + 1;
      EEPROM.get(lastAddress,params);
      EEPROM.put(eeAddress,params);
      EEPROM.put(0, uint8_t(count -1));
  }
  Serial.println(F("{\"action\":\"eeprom-delete\",\"result\":\"done\"}"));
}

void eepromAppend() {
  uint8_t count;
  EEPROM.get(0,count);
  EEPROM.put(0, uint8_t(count+1));
  int eeAddress = count * sizeof(LoginParams) + 1;
  LoginParams params;
  EEPROM.put(eeAddress,params);
  eepromWrite(String(count),true);
}

void eepromList() {
  uint8_t count;
  EEPROM.get(0,count);
  Serial.print("[");
  LoginParams params;
  for(uint8_t i = 0; i < count; i++) {
    int eeAddress = i * sizeof(LoginParams) + 1;
    EEPROM.get(eeAddress, params);
    Serial.print(F("{\"idx\":\""));
    Serial.print(i);
    Serial.print(F("\",\"sysname\":\""));
    Serial.print(params.sysname);
    Serial.print(F("\",\"platform\":\""));
    Serial.print(params.platform);
    Serial.print(F("\",\"uid\":\""));
    Serial.print(params.uid);
    Serial.print(F("\""));
    Serial.print(F("}"));
    if (i<count-1){
      Serial.print(F(","));
    }
  }
  Serial.println("]");
}

void getEEPROMCount() {
  uint8_t count;
  EEPROM.get(0,count);
  Serial.print("{\"action\":\"eeprom-readcount\",\"result\":\"");
  Serial.print(count);
  Serial.println("\"}");
}

void cardRead() {
  #ifdef DEBUG
    String ringUid;
    uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0};  // Buffer to store the returned UID
    uint8_t uidLength; // Length of the UID (4 or 7 bytes depending on ISO14443A card type
    uint8_t success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, &uid[0], &uidLength);
    if (success) {
      ringUid = charArrayToHex(uid,uidLength);
      Serial.print(F("ringUID:"));
      Serial.println(ringUid); 
      LoginParams params;
      int idx = getCardInfoFromEEPROM(ringUid, params);
      if (idx > -1) {
        uint8_t key[6];
        for(uint8_t i = 0; i<6; i++) {
          key[i] = uint8_t(params.sectorpasswd[i]);
        }
        success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, key);
        if (!success) {
          #ifdef DEBUG
            Serial.println(F("CardREAD: KeyA sector passwd not authenticate. Try defaultKeyB"));
          #endif
          nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);//WORKAROUND
          success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, defaultKeyB);
        }
        if (success) {
            uint8_t data[16];
            success = nfc.mifareclassic_ReadDataBlock(4, data);
            if (success) {
              Serial.println(F("Reading Block 4:"));
              nfc.PrintHexChar(data, 16);
              Serial.println("");
            } else {
              Serial.println(F("Unable to read the requested data block"));
            }
  
            success = nfc.mifareclassic_ReadDataBlock(7, data);
            if (success) {
              Serial.println(F("Reading Block 7:"));
              nfc.PrintHexChar(data, 16);
              Serial.println("");
            } else {
              Serial.println(F("Unable to read the requested trailer block"));
            }
  
        } else {
          Serial.println(F("Authenticatoin failed"));
        }
      } else {
        Serial.println(F("uid not found"));
      }
    } else {
      Serial.println(F("Card not fouund"));
    }
  #else
    Serial.println("{\"action\":\"card-read\",\"result\":\"false\",\"details\":\"Function allowed only for debug\"}");
  #endif
}

void cardWrite() {
  String ringUid;
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0};  // Buffer to store the returned UID
  uint8_t uidLength; // Length of the UID (4 or 7 bytes depending on ISO14443A card type
  uint8_t success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, &uid[0], &uidLength);
  if (success) {
    ringUid = charArrayToHex(uid,uidLength);
    LoginParams params;
    int idx = getCardInfoFromEEPROM(ringUid, params);
    if (idx > -1) {
      #ifdef DEBUG
        Serial.print(F("ringUID:"));
        Serial.println(ringUid);
      #endif
      uint8_t key[6];
      for(uint8_t i = 0; i<6; i++) {
        key[i] = uint8_t(params.sectorpasswd[i]);
      }
      success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, key);
      if (!success) {
        Serial.println(F("CardWrite: Sector passwd not authenticate for data block, try defaultKeyB"));
        nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);//WORKAROUND
        success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, defaultKeyB);
      }
      if (success) {
        String passwd = getValue(request_line,':',1);
        String newSectorPasswd = getValue(request_line,':',2);
        #ifdef DEBUG
          Serial.print(F("password:"));
          Serial.println(passwd);
        #endif
        uint8_t data[16];
        bool endChar = false;
        for(uint8_t i = 0; i < 16; i++) {
          data[i] = uint8_t(endChar ? char(0) : passwd[i]);
          #ifdef DEBUG
            Serial.print(passwd[i]);
            Serial.print(F("("));
            Serial.print(String(data[i], HEX));
            Serial.print(F(")"));
          #endif
          if (passwd[i] == char(0))
            endChar = true;
        }
        #ifdef DEBUG
          Serial.println("");
          
          for(uint8_t i = 0; i < 16; i++) {
            Serial.print(char(data[i]));
          }
          Serial.println("");
      
          Serial.print(F("CardWrite: The 4. memory block is first: "));
          Serial.println(nfc.mifareclassic_IsFirstBlock(4)?"true":"false");
        #endif
        #ifdef DEBUG
          Serial.println(F("CardWrite: Data:"));
          nfc.PrintHexChar(data, 16);
        #endif
        success = nfc.mifareclassic_WriteDataBlock (4, data);

        if (newSectorPasswd != "") {
          uint8_t newKey[6];
          for(uint8_t i = 0; i<6; i++) {
            newKey[i] = uint8_t(newSectorPasswd[i]);
          }
          uint8_t sectorTrailerBlockIdx = BLOCK_NUMBER_OF_SECTOR_TRAILER(1);
          uint8_t success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, sectorTrailerBlockIdx, 0, (uint8_t *)key);
        
          if (!success) {
            #ifdef DEBUG
              Serial.println("CardWrite: KeyA not authenticate, try default Sector password");
            #endif
            nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);//WORKAROUND
            success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, sectorTrailerBlockIdx, 0, (uint8_t *)defaultKeyB);
          }
        
          if (success) {
            uint8_t blockBuffer[16];
            memset(blockBuffer, 0, sizeof(blockBuffer));
            
            memcpy(blockBuffer, newKey, sizeof(newKey));
            memcpy(blockBuffer + 6, blankAccessBits, sizeof(blankAccessBits));
            blockBuffer[9] = 0x69;
            
            memcpy(blockBuffer + 10, newKey, sizeof(newKey));
            success = nfc.mifareclassic_WriteDataBlock(7, blockBuffer);
            if (success)
            {
              #ifdef DEBUG
                Serial.println(F("Trailer block:"));
                nfc.PrintHexChar(blockBuffer, 16);
              #endif
              newSectorPasswd.toCharArray(params.sectorpasswd, 7);
              int eeAddress = idx * sizeof(LoginParams) + 1;
              EEPROM.put(eeAddress, params);
            } else {
              Serial.println("{\"action\":\"card-write\",\"result\":\"false\",\"details\":\"Unable to write trailer block of sector\"}");
            }
          }  
        }
        Serial.println("{\"action\":\"card-write\",\"result\":\"true\",\"details\":\"Card write done\"}");
      } else {
        Serial.println("{\"action\":\"card-write\",\"result\":\"false\",\"details\":\"Sector authenticatoin failed\"}");
      }
    } else {
      Serial.println("{\"action\":\"card-write\",\"result\":\"false\",\"details\":\"Uid not found\"}");
    }

  } else {
    Serial.println("{\"action\":\"card-write\",\"result\":\"false\",\"details\":\"Card for read not found\"}");
  }
}

void cardErase(){
  String ringUid;
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0};  // Buffer to store the returned UID
  uint8_t uidLength; // Length of the UID (4 or 7 bytes depending on ISO14443A card type
  uint8_t success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, &uid[0], &uidLength);
  if (success) {
    ringUid = charArrayToHex(uid,uidLength);
    LoginParams params;
    int idx = getCardInfoFromEEPROM(ringUid, params);
    if (idx > -1) {
      #ifdef DEBUG
        Serial.print(F("ringUID:"));
        Serial.println(ringUid);
      #endif
      uint8_t key[6];
      for(uint8_t i = 0; i<6; i++) {
        key[i] = uint8_t(params.sectorpasswd[i]);
      }
      success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, key);
      if (!success) {
        Serial.println(F("CardErase: Sector passwd not authenticate for data block, try defaultKeyB"));
        nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);//WORKAROUND
        success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, defaultKeyB);
      }
      if (success) {
          uint8_t data[16];
          memset(data, 0, sizeof(data));
          #ifdef DEBUG
            nfc.PrintHexChar(data, 16);
          #endif
          success = nfc.mifareclassic_WriteDataBlock (4, data);  

          uint8_t sectorTrailerBlockIdx = BLOCK_NUMBER_OF_SECTOR_TRAILER(1);
          uint8_t success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, sectorTrailerBlockIdx, 0, (uint8_t *)key);

          uint8_t blockBuffer[16];
          memset(blockBuffer, 0, sizeof(blockBuffer));
          
          memcpy(blockBuffer, defaultKeyB, sizeof(defaultKeyB));
          memcpy(blockBuffer + 6, blankAccessBits, sizeof(blankAccessBits));
          blockBuffer[9] = 0x69;
          
          memcpy(blockBuffer + 10, defaultKeyB, sizeof(defaultKeyB));
          if (nfc.mifareclassic_WriteDataBlock(7, blockBuffer)) {
            Serial.println("{\"action\":\"card-erase\",\"result\":\"true\",\"details\":\"Card erase done\"}");
          } else {
            Serial.println("{\"action\":\"card-erase\",\"result\":\"false\",\"details\":\"Sector write failed\"}");
          }
      } else {
        Serial.println("{\"action\":\"card-erase\",\"result\":\"false\",\"details\":\"Sector authenticatoin failed\"}");
      }
    }
  }
}

void sendKeys(LoginParams &params, String passwd) {
  #ifdef DEBUG
    Serial.print(F("ringUid:"));
    Serial.println(params.uid);
    Serial.print(F("platform:("));
    Serial.print(String(params.platform, HEX));
    Serial.print(F(")"));
    Serial.println(params.platform);
  #endif
  if ((String("g").indexOf(params.platform) == 0) || String("k").indexOf(params.platform) == 0) {
    //Keyboard.press(KEY_LEFT_GUI);
    //Keyboard.press('l');
    Keyboard.press(KEY_RETURN);
  } else if (String("t").indexOf(params.platform) == 0) {
    //Terminal not require key prefix
  } else {
    Keyboard.press(KEY_LEFT_CTRL);
    Keyboard.press(KEY_LEFT_ALT);
    Keyboard.press(KEY_DELETE);
  }
  delay(100);
  Keyboard.releaseAll();
  delay(500);  
  Keyboard.print(passwd);
  delay(100);
  Keyboard.press(KEY_RETURN);
  delay(100);
  Keyboard.releaseAll();
  delay(1000);
}

int getCardInfoFromEEPROM(String ringUid, LoginParams &p) {
  uint8_t count;
  EEPROM.get(0,count);
  int idx = -1;
  for(int i = 0; i < count; i++) {
    EEPROM.get(i * sizeof(LoginParams) +1, p);
    if (ringUid.indexOf(p.uid) == 0) {
      idx = i;
      break;
    }
  }
  return idx;
}

String charArrayToHex(uint8_t uid[], byte uidLength) {
  String result;
  for (uint8_t i=0; i < uidLength; i++){
    if(uid[i] < 0x10) {
      result += '0';
    }
    result += String(uid[i], HEX);
  }
  return result; 
}

String getValue(String data, char separator, int index) {
    int found = 0;
    int strIndex[] = { 0, -1 };
    int maxIndex = data.length() - 1;

    for (int i = 0; i <= maxIndex && found <= index; i++) {
        if (data.charAt(i) == separator || i == maxIndex) {
            found++;
            strIndex[0] = strIndex[1] + 1;
            strIndex[1] = (i == maxIndex) ? i+1 : i;
        }
    }
    String sub = data.substring(strIndex[0], strIndex[1]);
    String result = (found > index) && (sub.indexOf(separator)==-1) ? sub : "";
    return result;
}

void dumpMemory() {
  uint8_t success;
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };
  uint8_t uidLength;
  uint8_t currentblock;
  bool authenticated = false;
  uint8_t data[16];

  // Keyb on NDEF and Mifare Classic should be the same
  uint8_t keyuniversal[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
  if (success) {
    // Display some basic information about the card
    Serial.println(F("Found an ISO14443A card"));
    Serial.print(F("  UID Length: "));Serial.print(uidLength, DEC);Serial.println(F(" bytes"));
    Serial.print(F("  UID Value: "));
    for (uint8_t i = 0; i < uidLength; i++) {
      Serial.print(uid[i], HEX);
      Serial.print(' ');
    }
    Serial.println("");

    if (uidLength == 4)
    {
      Serial.println("Seems to be a Mifare Classic card (4 byte UID)");

      for (currentblock = 0; currentblock < 64; currentblock++)
      {
        if (nfc.mifareclassic_IsFirstBlock(currentblock)) authenticated = false;
      
        if (!authenticated)
        {
          Serial.print(F("------------------------Sector "));Serial.print(currentblock/4, DEC);Serial.println(F("-------------------------"));
          if (currentblock == 0)
          {
              success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 1, keyuniversal);
          }
          else
          {
              success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 1, keyuniversal);
          }
          if (success)
          {
            authenticated = true;
          }
          else
          {
            Serial.println(F("Authentication error"));
            success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength); //WORKAROUND
          }
        }
        if (!authenticated)
        {
          Serial.print(F("Block "));Serial.print(currentblock, DEC);Serial.println(F(" unable to authenticate"));
        }
        else
        {
          success = nfc.mifareclassic_ReadDataBlock(currentblock, data);
          if (success)
          {
            Serial.print(F("Block "));Serial.print(currentblock, DEC);
            if (currentblock < 10)
            {
              Serial.print("  ");
            }
            else
            {
              Serial.print(" ");
            }
            nfc.PrintHexChar(data, 16);
          }
          else
          {
            Serial.print(F("Block "));Serial.print(currentblock, DEC);
            Serial.println(F(" unable to read this block"));
          }
        }
      }
    }
  }
}

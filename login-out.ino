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

#define DEBUG;

const uint8_t defaultKeyA[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
const uint8_t defaultKeyB[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

uint8_t blankAccessBits[3] = { 0xff, 0x07, 0x80 };

void setup() {
  Serial.begin(9600);
  #ifdef DEBUG
    while(!Serial);
  #endif
  Serial.println("Start control...");
  nfc.begin();
  
  #ifdef DEBUG
    uint32_t versiondata = nfc.getFirmwareVersion();
    if (! versiondata) {
      Serial.print("Didn't find PN53x board");
      while (1); // halt
    }
    // Got ok data, print it out!
    Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX); 
    Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC); 
    Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);
  #endif
  nfc.SAMConfig(); // configure board to read RFID tags  
  Keyboard.begin();
} 

String request_line;
bool cardSetupMode = false;
// "w:0:system_name:w:12345678:sectorpwd"

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
        eepromWrite();
      } else if (action == "cr") {
        cardRead();
      } else if (action == "cw") {
        cardWrite();
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
        #ifdef DEBUG
          Serial.print(F("LogInOut: Card detected[idx="));
          Serial.print(idx);
          Serial.println(F("]. Try authentication..."));
        #endif
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
            Serial.println(F("LogInOut: Card read error!"));
            delay(1000);
          }
        } else {
          Serial.println(F("LogInOut: authentication error at card read!"));
          delay(1000);
        }        
      } else {
        Serial.println(ringUid);
        Serial.println(F("LogInOut: card not registered."));
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
  int eeAddress = targetIdx.toInt() * sizeof(LoginParams);
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

void eepromWrite() {
  String targetIdx = getValue(request_line,':',1);
  int eeAddress = targetIdx.toInt() * sizeof(LoginParams);
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
  if (targetPlatform.length()>0) {
    params.platform = targetPlatform[0];
  }
  targetNFCUID.toCharArray(params.uid, 15);
  targetSectorPasswd.toCharArray(params.sectorpasswd, 7);
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
    Serial.println(params.sectorpasswd);
  #endif
  EEPROM.put(eeAddress, params);
}

void cardRead() {
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
        Serial.println(F("CardREAD: KeyA sector passwd not authenticate. Try defaultKeyB"));
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
            Serial.println("Reading Block 7:");
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
      Serial.print(F("ringUID:"));
      Serial.println(ringUid);
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
          Serial.print("password:");
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
            Serial.println("CardWrite: KeyA not authenticate, try default Sector password");
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
            nfc.mifareclassic_WriteDataBlock(7, blockBuffer);
            if (true)
            {
              #ifdef DEBUG
                Serial.println(F("Trailer block:"));
                nfc.PrintHexChar(blockBuffer, 16);
              #endif
              newSectorPasswd.toCharArray(params.sectorpasswd, 7);
              int eeAddress = idx * sizeof(LoginParams);
              EEPROM.put(eeAddress, params);
            } else {
              Serial.print("Unable to write trailer block of sector");
            }
          }  
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
}

void writeSectorTrailer(uint8_t key[], uint8_t newKey[], uint8_t uid[], uint8_t uidLength) {
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
  if (String("g").indexOf(params.platform) == 0) {
    Keyboard.press(KEY_LEFT_GUI);
    Keyboard.press('l');
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
    int idx = -1;
    for(int i = 0; i < 16; i++) {
      EEPROM.get(i * sizeof(LoginParams), p);
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
  uint8_t success;                          // Flag to check if there was an error with the PN532
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID
  uint8_t uidLength;                        // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  uint8_t currentblock;                     // Counter to keep track of which block we're on
  bool authenticated = false;               // Flag to indicate if the sector is authenticated
  uint8_t data[16];                         // Array to store block data during reads

  // Keyb on NDEF and Mifare Classic should be the same
  uint8_t keyuniversal[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
  if (success) {
    // Display some basic information about the card
    Serial.println("Found an ISO14443A card");
    Serial.print("  UID Length: ");Serial.print(uidLength, DEC);Serial.println(" bytes");
    Serial.print("  UID Value: ");
    for (uint8_t i = 0; i < uidLength; i++) {
      Serial.print(uid[i], HEX);
      Serial.print(' ');
    }
    Serial.println("");

    if (uidLength == 4)
    {
      // We probably have a Mifare Classic card ...
      Serial.println("Seems to be a Mifare Classic card (4 byte UID)");

      for (currentblock = 0; currentblock < 64; currentblock++)
      {
        // Check if this is a new block so that we can reauthenticate
        if (nfc.mifareclassic_IsFirstBlock(currentblock)) authenticated = false;
      
        // If the sector hasn't been authenticated, do so first
        if (!authenticated)
        {
          // Starting of a new sector ... try to to authenticate
          Serial.print("------------------------Sector ");Serial.print(currentblock/4, DEC);Serial.println("-------------------------");
          if (currentblock == 0)
          {
              // This will be 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF for Mifare Classic (non-NDEF!)
              // or 0xA0 0xA1 0xA2 0xA3 0xA4 0xA5 for NDEF formatted cards using key a,
              // but keyb should be the same for both (0xFF 0xFF 0xFF 0xFF 0xFF 0xFF)
              success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 1, keyuniversal);
          }
          else
          {
              // This will be 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF for Mifare Classic (non-NDEF!)
              // or 0xD3 0xF7 0xD3 0xF7 0xD3 0xF7 for NDEF formatted cards using key a,
              // but keyb should be the same for both (0xFF 0xFF 0xFF 0xFF 0xFF 0xFF)
              success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 1, keyuniversal);
          }
          if (success)
          {
            authenticated = true;
          }
          else
          {
            Serial.println("Authentication error");
            success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength); //WORKAROUND
          }
        }
        // If we're still not authenticated just skip the block
        if (!authenticated)
        {
          Serial.print("Block ");Serial.print(currentblock, DEC);Serial.println(" unable to authenticate");
        }
        else
        {
          // Authenticated ... we should be able to read the block now
          // Dump the data into the 'data' array
          success = nfc.mifareclassic_ReadDataBlock(currentblock, data);
          if (success)
          {
            // Read successful
            Serial.print("Block ");Serial.print(currentblock, DEC);
            if (currentblock < 10)
            {
              Serial.print("  ");
            }
            else
            {
              Serial.print(" ");
            }
            // Dump the raw data
            nfc.PrintHexChar(data, 16);
          }
          else
          {
            // Oops ... something happened
            Serial.print("Block ");Serial.print(currentblock, DEC);
            Serial.println(" unable to read this block");
          }
        }
      }
    }
  }
}
#!/usr/bin/python

#############################################################################
# Original code from:  https://nickvsnetworking.com/reverse-md5-on-sip-auth/#
# Modified by Jason Murley (www.calltower.com)                              #
# Additions:                                                                #
#             Added ability to input aruguments for calculating hash        #
#             Added ability to calculate hashes from multiple algorithms    #
#             and qops                                                      #
#             Can leave out digest URI if it is the same as digest realm    #
#############################################################################

import sys
import hashlib

# program info Variables
__author__ = 'Jason Murley'
__credits__ = ['Jason Murley', 'nickvsnetworking']
__license__ = 'GPL'
__version__ = '1.01'
__maintainer__ = 'RNJMUR'
__email__ = 'jmurley@calltower.com'
__status__ = 'Prod'

class sipDigest():
    '''Class for calculating hash for SIP digest'''
    #Constructor
    def __init__(self, nonce, nonceCount, realm, cnonce, qop, algorithm, password, username, entitybody, digesturi="none"):
        #initialize values from input arguments
        self.nonce = nonce
        self.nonceCount = nonceCount
        self.realm = realm
        self.cnonce = cnonce
        self.qop = qop
        self.algorithm = algorithm
        self.password = password
        self.username = username
        self.entitybody = entitybody
        #check if digesturi was passed.
        #if not then set digesturi to digest realm
        #if yes then set digesturi
        if (digesturi == "none"):
            self.digesturi = realm
        else:
            self.digesturi = digesturi

    def doHash(self):
        '''Returns the MD5 hash based on the alogorithm and qop
        @return "ERROR" if has cannot be calulated or the MD5 
                encoded string'''
        #check which algorithm needs to be used for calculating HA1
        if (self.algorithm == "MD5") or (self.algorithm == "md5") or (self.algorithm == "none"):
            HA1str = self.username + ":" + self.realm + ":" + self.password
            self.HA1enc = (hashlib.md5(HA1str.encode()).hexdigest())
        elif (self.algorithm == "MD5-sess") or (self.algorithm == "md5-sess"):
            HA1str1 = self.username + ":" + self.realm + ":" + self.password
            HA1enc1 = (hashlib.md5(HA1str1.encode()).hexdigest())
            HA1str2 = HA1enc1 + ":" + self.nonce + ":" + self.cnonce
            self.HA1enc = (hashlib.md5(HA1str2.encode()).hexdigest())
        else:
            #return ERROR if MD5 value is invalid
            return "ERROR"
        #check which qop to use for calculating HA2
        if (self.qop == "auth") or (self.qop == "none"):
            HA2str = "REGISTER:" + self.digesturi
            self.HA2enc = (hashlib.md5(HA2str.encode()).hexdigest())
        elif (self.qop == "auth-init"):
            HA2str1 = "REGISTER:" + self.digesturi
            HA2enc1 = (hashlib.md5(self.entitybody.encode()).hexdigest())
            HA2str = HA2str1 + ":" + HA2enc1
            self.HA2enc = (hashlib.md5(HA2str.encode()).hexdigest())
        else:
            #return ERROR if qop value is invalid
            return "ERROR"
        #check which qop is used for calculating final MD5 hash
        if (self.qop == "auth") or (self.qop == "auth-init"):
            self.responsestr = self.HA1enc + ":" + self.nonce + ":" + self.nonceCount + ":" + self.cnonce + ":" + self.qop + ":" + self.HA2enc
        elif (self.qop == "none"):
            self.responsestr = self.HA1enc + ":" + self.nonce + ":" + self.HA2enc
        else:
            #return ERROR if qop value is invalid
            return "ERROR"
        
        #return the final MD5 hash
        return str((hashlib.md5(self.responsestr.encode()).hexdigest()))

    def printMD5(self):
        '''Prints the Values to screen'''
        #Run doHash function
        responseenc = self.doHash()
        
        #If doHash returns ERROR print error message otherwise output values
        if (responseenc == "ERROR"):
            print("Error Calculating hash!  Check your input values!\n")
        else:
            print("username  : " + self.username)
            print("password  : " + self.password)
            print("nonce     : " + self.nonce)
            print("nonceCount: " + self.nonceCount)
            print("realm     : " + self.realm)
            print("cnonce    : " + self.cnonce)
            print("qop       : " + self.qop)
            print("algorithm : " + self.algorithm)
            print("\n")
            print("HA1 Encrypted  : " + self.HA1enc)
            print("HA2 Encrypted  : " + self.HA2enc)
            print("Response String: " + self.responsestr)
            print("\n")
            print("Response Encrypted: " + responseenc)

if __name__ == '__main__':
    '''Main program'''
    #Static CLI help if improper args are used
    _CLI_INV_ARGS = "\nInvalid commandline arguments!   Arguments should be: nonce nonceCount realm cnonce qop algorithm password username entitybody (optional Method URI)\n\
digest URI is only required if it is different than the digest realm.\n\n\
Example: filename    nonce    ncount         digest realm   cnonce   qop  algorithm  password  username  entity body  digest URI (optional)\n\
         ----------------------------------------------------------------------------------------------------------------------------------\n\
command: sip_md5.py 34000dfg 00000001 sip:sip.example.com  ytedf745h auth    MD5     password 7001234567 EntityBody    sip:proxy.sip.com\n\
\nValid choices for qop should be either auth, auth-init, or none\n\
\nValid choices for MD5 should be MD5 or MD5-sess\n\
\nIf there is no entity body just put none.  If entity body includes spaces surround the entity body with double quotes."
    #Check if correct number of arguments are given
    if len(sys.argv) == 10:
        #initialize sipDigest with argument values
        newMD5 = sipDigest(str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3]), str(sys.argv[4]), str(sys.argv[5]), 
                           str(sys.argv[6]), str(sys.argv[7]), str(sys.argv[8]), str(sys.argv[9]))
        #Run printMD5 which will calculate the hash then output to the screen
        newMD5.printMD5()
    elif len(sys.argv) == 11:
        #initialize sipDigest with argument values
        newMD5 = sipDigest(str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3]), str(sys.argv[4]), str(sys.argv[5]), 
                           str(sys.argv[6]), str(sys.argv[7]), str(sys.argv[8]), str(sys.argv[9]), str(sys.argv[10]))
        #Run printMD5 which will calculate the hash then output to the screen
        newMD5.printMD5()
    else:
        sys.exit(_CLI_INV_ARGS)
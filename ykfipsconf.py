#!/usr/bin/python
import subprocess
import re
import sys, getopt
import json

#### CONFIG LOADS HERE ####
with open('/etc/ykConfig/secrets.json') as json_data_file:
    secrets = json.load(json_data_file)


default_otp_access_code = secrets['ykConfig']['otp_access_code']
default_oath_password = secrets['ykConfig']['oath_password']
default_fido_admin_pin = secrets['ykConfig']['fido_admin_pin']
default_u2f_pin = secrets['ykConfig']['u2f_pin']
debug = False
#### END CONFIG LOAD ####

class Provisioner:
    def __init__(self):
        self.infile = None
        self.outfile = None
        self.keys = []
        self.clearKey = False

    def exportCSV(self):
        output = open(self.outfile,"a")
        outputstr = ""
        for entries in self.keys:
            outputstr = entries[0] + "," + entries[1] + "," + entries[2]  + "\n"
            output.write(outputstr)
        output.close()
        print("Wrote ["+str(len(self.keys))+ "] keys to file: " + self.outfile + " as csv")

    def checkKey(self,yubiKey):
        for key in self.keys:
            if key[0] == yubiKey.serial:
                return "Duplicate Serial"
        return None

class Yubikey:
    def __init__(self):
        self.type = None
        self.locked = None
        self.fips = None
        self.fipsApps = []
        self.serial = None
        self.identity = []
        self.modes = None 
        # might need to rethink the next line
        self.queryKey()

    def checkInfo(self):
        cmdArgs="info"
        cmdResult=runYkMan(cmdArgs)
        regexp = '^Device type: (YubiKey \w+)\nSerial number: (\d+)\n'
        values = re.match(regexp,cmdResult)
        self.type = values.groups()[0]
        self.serial = values.groups()[1]
        regForMode = 'Enabled USB interfaces: (.*)\n'
        values = re.findall(regForMode,cmdResult)
        if values is not None:
            self.modes = values[0].split('+')

    def queryKey(self):
        self.fipsApps = []
        self.checkInfo()
        #holy crap is the checkFips call slow
        #only do if we really need to
        if self.type == "YubiKey FIPS":
            self.checkFips()

    def checkFips(self):
        cmdArgs="info -c"
        cmdResult=runYkMan(cmdArgs)
        regexp = 'FIPS Approved Mode: (\w+)\n'
        values = re.findall(regexp,cmdResult)
        self.fips = values[0]
        regmodes = 'FIPS Approved Mode: \w+\n(.*)\n(.*)\n(.*)'
        values = re.findall(regmodes,cmdResult)
        if values is not None:
            for val in values:
                for v in val:
                    if re.match('  FIDO U2F:',v):
                        splitval = re.split(': ',v)
                        self.fipsApps.append([splitval[0].strip(),splitval[1]])
                    if re.match('  OATH:',v):
                        splitval = re.split(': ',v)
                        self.fipsApps.append([splitval[0].strip(),splitval[1]])
                    if re.match('  OTP:',v):
                        splitval = re.split(': ',v)
                        self.fipsApps.append([splitval[0].strip(),splitval[1]])

    def configMode(self):
        mc = 0
        resetMode = False
        for m in self.modes:
            # increment "required" modes
            if m == 'OTP':
                mc += 1
            if m == 'FIDO':
                mc += 1
            # flag for reset if "disabled" modes are enabled
            if m == 'CCID':
                mc += 1
            #    print('need to disable: ' + m)
            #    resetMode = True
            if m == 'OpenPGP':
                print('need to disable: ' + m)
                resetMode = True
            if m == 'PIV':
                print('need to disable: ' + m)
                resetMode = True
        # reset modes to OTP+FIDO if that is not the current state
        if resetMode == True or mc < 3:
            self.setMode()

    def setMode(self,status=None):
        #default for FIPS keys
        if status is None:
            mode = 'OTP+FIDO+CCID'
        elif status == 'Finalize':
            mode = 'OTP'
        print("setting mode to: " + mode)
        runYkMan('mode '+ mode +' -f')
        raw_input("Press Enter after reinserting key...")

    def resetOtp(self,access_code=None):
        if access_code is not None:
            delete_otp = 'otp --access-code ' + access_code + ' delete '
            returned_d1 = runYkMan(delete_otp + '1 -f')
            returned_d2 = runYkMan(delete_otp + '2 -f')
            if returned_d1 is None or returned_d2 is None:
                print('ERROR: could not delete one or more otp slots')
                return 2
        
        delete_oath = 'oath reset -f'
        returned_oath = runYkMan(delete_oath)
        if returned_oath is None:
            print('ERROR: could not reset oath app')
    
    # this is really a forward operation only.
    # we should never run this if the FIPS mode for u2f is "Yes"
    # was lock, now setpin since this is more descriptive.
    # lock will need some additional safety checks, as screwing this up
    # can reset the app and we've got an $80 brick on our hands
    def setpinU2F(self,u2f_admin_pin=None):
        if u2f_admin_pin is None:
            print("ERROR: no u2f_pin provided")
            return 2
        u2f_lock = 'fido set-pin --u2f -n ' + u2f_admin_pin 
        returned_u2f = runYkMan(u2f_lock)
        if returned_u2f is None:
            print("ERROR: failed to set oath code")
            return 2

    # we originally were planning to disable the CCID app
    # but it appears you must have the app *enabled* in order
    # to meet the requirements for FIPS mode enablement
    def lockOath(self,oath_password=None):
        if oath_password is None:
            print("ERROR: no oath password provided")
            return 2
        oath_lock = 'oath set-password -n ' + oath_password
        returned_oath=runYkMan(oath_lock)
        if returned_oath is None:
            print("ERROR: failed to set oath code")
            return 2

    def generateOTP(self,access_code=None):
        # default for FIPS keys
        # changeme for the love of all
        if access_code==None:
            access_code = '010203040506'
        # sets the config for the second slot to be "empty"
        # required for fips mode enablement
        # see Fips manual for why (https://support.yubico.com/support/solutions/articles/15000011059-yubikey-fips-series-technical-manual)
        otp_empty = 'otp --access-code ' + access_code + ' chalresp 2 000000000000000000000000000000 -f'
        returned_empty = runYkMan(otp_empty)
        if returned_empty is None:  # returns None if an exception gets tripped
            print("ERROR: failed to set slot 2 to empty")
            return 2
        # failure mode for the above run returns a 2, and sends output to stderr
        ''' mycroft-local@mycroft-mbp yksetup % '/Applications/YubiKey Manager.app/Contents/MacOS/ykman' otp --access-code 000000000000 chalresp 2 000000000000000000000000000000 -f > testout.error
            Usage: ykman otp chalresp [OPTIONS] [1|2] [KEY]
            Try "ykman otp chalresp -h" for help.

            Error: Failed to write to the YubiKey. Make sure the device does not have restricted access.
            mycroft-local@mycroft-mbp yksetup % '''

        # uses the serial number as the public identity
        # randomly generates both private key and seed values
        otp_setup = 'otp --access-code ' + access_code + ' yubiotp -S -g -G 1 -f'
        # we need to parse the output here
        # looks something like the following
        ''' Using YubiKey serial as public ID: vvcccckuncnl
            Using a randomly generated private ID: 7ebf92fdc832
            Using a randomly generated secret key: 2a36148167aafecc3e3205195e36d223
        '''
        returned_setup=runYkMan(otp_setup)
        if returned_setup is None:
            print("ERROR: unable to configure otp keys for slot 1")
            return 2
        else:
            ykvalues = re.findall(': (.*)',returned_setup)
            #c = 1
            if ykvalues is not None:
                for v in ykvalues:
                    self.identity.append(v.strip())
                if debug == True: print("self.identity:",self.identity)
            else:
                print(returned_setup)

        # set the defaults for slot 1, no enter key + short press defaulted
        # return non 0 if we see an issue
        otp_opts = 'otp --access-code ' + access_code + ' settings --no-enter 1 -f'
        if runYkMan(otp_opts) is None:
            print("ERROR: unable to configure options for slot 1")
            return 2
        return 0
        
 # -end of class-        
def runYkMan(args):
        cmd = 'ykman'
        cmdArgs=args
        cmdPath='/Applications/YubiKey\ Manager.app/Contents/MacOS/'
        cmdFull = [cmdPath+'/'+cmd + " "+ cmdArgs]
        try:
            retvar = subprocess.check_output( [cmdPath+'/'+cmd + " "+ cmdArgs], shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print("Error on: ", cmdFull)
            retvar = None
        if debug == True: print(cmdFull,retvar)
        return retvar


def argHandler(argv,execPath,provis):
    infile = ''
    outfile = ''
    try:
        opts, args = getopt.getopt(argv,"rhd:o:", ["outfile="])
    except getopt.GetoptError:
        print("usage:(e) "+execPath + " -o outputcsv")
        sys.exit(2)
    clearKey = None
    for opt, arg in opts:
        if opt == '-h':
            print("usage: "+execPath + " -o outputcsv")
            sys.exit()
        elif opt == '-r':
            print("Resetting Keys...")
            provis.clearKey = True
        elif opt in ("-o", "--outfile"):
            provis.outfile = arg
    if (provis.outfile == None) and provis.clearKey is not True:
        print("usage(f): "+execPath + " -o outputcsv")
        sys.exit(2)

def Main():
    # setup provisioner class
    provis = Provisioner()
    argHandler(sys.argv[1:],sys.argv[0],provis)
    print("Yubikey Bulk Provisioning Tool")
    while True:
        if provis.clearKey == False:
            # start the workflow
            if debug == True: print("Sending results to: " + provis.outfile)
            if raw_input("Insert yubikey and press Enter (x to exit):").lower() == 'x':
                break
            yk = Yubikey()
            if provis.checkKey(yk) is not None:
                print("WARNING: DUPLICATE SERIAL. SKIPPING!")
                continue
            yk.configMode()
            if yk.type == "YubiKey FIPS" and yk.fips is not None:
                if yk.fips == 'No':
                    # we need to enable fips mode
                    # we need a conditional to check fipsApps and
                    for fipsstate in yk.fipsApps:
                            if debug == True: print(fipsstate)
                            if ['OTP','No'] == fipsstate:
                                # generate keys + lockdown config for each
                                yk.generateOTP(access_code=default_otp_access_code)
                            if ['FIDO U2F','No'] == fipsstate:
                                # start web enrollment flow
                                # pause wait for enter 
                                # then lock the key
                                yk.setpinU2F(u2f_admin_pin=default_u2f_pin)
                                # need to create unlock subroutine, not currently used.
                                #yk.unlockU2F(u2f_admin_pin=default_u2f_pin)
                                # registraiton steps could happen here re: u2f.
                            if ['OATH', 'No'] == fipsstate:
                                # lockdown oath app
                                yk.lockOath(oath_password=default_oath_password)
            else:
                yk.generateOTP(access_code=default_otp_access_code)
            yk.queryKey()
            if debug == True: print(yk.type,yk.serial,yk.fips,yk.modes,yk.fipsApps)
            try:
                provis.keys.append([yk.serial,yk.identity[1],yk.identity[2]])
            except IndexError:
                print("ERROR: Key Appears to be pre-configured...")
                continue
            if yk.fips == 'Yes':
                # we would then set mode to otp only.
    #            yk.resetOtp(access_code=default_otp_access_code)
    #            yk.setMode(status='Finalize')
    #            yk.generateOTP(access_code=default_otp_access_code)
                # instead of honoring the FIPS mode status of the disabled apps
                # when the unused modes are disabled they revert to "Fips mode NO"
                ''' Enabled USB interfaces: OTP

                    Applications
                    OTP     	Enabled      	
                    FIDO U2F	Disabled     	
                    OpenPGP 	Enabled      	
                    PIV     	Enabled      	
                    OATH    	Enabled      	
                    FIDO2   	Not available	

                    FIPS Approved Mode: No
                    FIDO U2F: No
                    OATH: No
                    OTP: Yes
                    '''
                print("Success, fips mode enabled")
                provis.exportCSV()
            else:
                provis.exportCSV()
        elif provis.clearKey == True:
            if raw_input("Insert yubikey and press Enter (x to exit):").lower() == 'x':
                break
            yk = Yubikey()
            yk.resetOtp(access_code=default_otp_access_code)

Main()


def testFipsInput():
    s="""Device type: YubiKey FIPS
Serial number: 10399930
Firmware version: 4.4.5
Enabled USB interfaces: OTP+FIDO

Applications
OTP     	Enabled      	
FIDO U2F	Enabled      	
OpenPGP 	Enabled      	
PIV     	Enabled      	
OATH    	Enabled      	
FIDO2   	Not available	

FIPS Approved Mode: No
  FIDO U2F: No
  OATH: No
  OTP: No"""
    return s

def testInput():
	s="""Device type: YubiKey 4
Serial number: 6330582
Firmware version: 4.3.5
Enabled USB interfaces: OTP+FIDO+CCID

Applications
OTP     	Enabled      	
FIDO U2F	Enabled      	
OpenPGP 	Enabled      	
PIV     	Enabled      	
OATH    	Enabled      	
FIDO2   	Not available"""
	return s

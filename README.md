KeePasswd
=========

KeePasswd is a sample application that accompanies my blog article [showing how KeePass 2.x authenticates a password]().

Usage
-----

      --file, -f=VALUE       Path to the KeePass2 KDBX database (required)
      --passwords, -p=VALUE  Comma seperated list of passwords to try (required)

      --header               Shows the header of the database file
      -h, -?, --help         Prints out the options

**Trying mutliple passwords**

    $> abc.exe -file "C:\ExampleDatabase.kdbx" -passwords a,b,c,test123

	The password is 'test123'


**Displaying header data**

    $> abc.exe -file "C:\ExampleDatabase.kdbx" -header

    Master Seed: 681576DF73AC6AE38A21494AF04723E1968168EE08CC4D1893F72D3F309E42BF
    Encryption IV: 5B61F08E5BDD401F72C0C43DA15E2700
    Transform Rounds: 6000
    Transform Seed: C723515A30197B562906A32BBC371FC8C9433DA589A499FF59587A62EC8F3055
    Expected Start-Bytes: A45D4E050BF15F3F66B357E1BDC86343C75D6A72CE976665C6E341D2EE015ADC
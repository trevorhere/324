#### Level 1

command: ```export BANDIT_LEVEL=1 && ./level1```

output: ```6/Q2LbNWe5a4KTk8ymUVrKuQ2J8B+/2+```

#### Level 2

command: ```./level2 2> /dev/null```

output: ```4utUC/pa/7fK5zU0Q3qPKPbmicmozKSc```

#### Level 3

command: ```more level3.txt | grep ^eget | awk '{print $2}'```

output: ```WvmlqTFW+sn+TgJD9nEifb2cFNaDYaL3```

#### Level 4

command: ```more level4.txt  | sort | awk '/./{line=$0} END{print line}' | base64 --decode```

output: ```eAyRe5KDtiqxDoeqVCABnj6hBMhCR/Bd```

#### Level 5

command: ```dig bandit.cs324.internet-measurement.cs.byu.edu TXT +short |  md5sum```

output: ```d9addec2125e48f5a24be719eb35f275```

#### Level 6

command: ```tar xvf level6.tar.gz -C /tmp/ | tr F L < /tmp/passwd ```

output: ```Jp1NL6O/H7uPUesDQ7r1TPLH2oGlTyHn```

#### Level 7

command:```  curl https://imaal.byu.edu/cs324/bandit.txt |  sha1sum| cut -c 1-32  ```

output: ```fb7cf39e8e0becdcd0468863cdc653e6```

#### Level 8

command/output:
```  
bandit7@imaal:~$ ./level8 
Countdown!
10!
9!
^Z
[1]+  Stopped                 ./level8
bandit7@imaal:~$ %1 fg
./level8
8!
7!
6!
5!
4!
3!
2!
1!
Uoux218Rtfi8Eg1UmIfZ9m4NErlTW+d9
```

#### Level 9

command:```sort level9.txt | uniq -c | sort -n | tail -1```

output: ```3 WWvs5PXxiY81gLjw60+mBccj6bGACwdU```

#### Level 10

output: ```Congratulations! You have reached Level 9 and are now officially a BYU bandit!```








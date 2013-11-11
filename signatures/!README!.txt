
[.Introduction.]
This directory contains signatures for how cached passwords appear in memory
for these applications. The goal being to build a database to allow automatic
dumping post compromise.

[.Methodology.]
- Place the passwords you're going to use in input.txt
- Start the application / supply password
- Run command similar to :

  Memgrep.exe -a 10 -b 10 -f input.txt -x -p [PID of Process] -q
 
  OR for an entire system scan
  
  Memgrep.exe -a 10 -b 10 -f input.txt -x -p -q
  
- Close the application
- Start the application / supply password

- Re-run command similar to :

  Memgrep.exe -a 10 -b 10 -f input.txt -x -p [PID of Process] -q
 
  OR for an entire system scan
  
  Memgrep.exe -a 10 -b 10 -f input.txt -x -p -q

If common bytes are before / after could be a good signature...


# TASK 3

```gcc task3.c -o task3

grep -aob "AAAAAAAAAA" task3

head -c 12352 task3 > prefix
                                                                                                                                              
./md5collgen -p prefix -o out1.bin out2.bin

ls -l out1.bin out2.bin

tail -c +12481 task3 > suffix

cat out1.bin suffix > prog1
cat out2.bin suffix > prog2

chmod +x prog1 prog2

md5sum prog1 prog2
./prog1
./prog2

cmp -l prog1 prog2 | head -n 10

xxd prog1 > prog1.hex
xxd prog2 > prog2.hex
diff prog1.hex prog2.hex 
```

# TASK 4

```gcc task4.c -o task4

head -c 12352 task4 > prefix
./md5collgen -p prefix -o out1.bin out2.bin

tail -c 128 out1.bin > block_P
tail -c 128 out2.bin > block_Q

tail -c +12609 task4 > suffix

cat out1.bin block_P suffix > benign_prog
cat out2.bin block_P suffix > malicious_prog

chmod +x benign_prog malicious_prog

./benign_prog                      
                                                                                                                                              
./malicious_prog           

md5sum benign_prog malicious_prog

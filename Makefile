#CFLAGS = -Ofast -flto
CFLAGS = -g

LIB_OBJS := buffered.o hc-128.o rabbit.o salsa20.o sosemanuk.o util.o umac.o
TESTS := algorithms_test buffering_test umac_test

libestream.a: $(LIB_OBJS)
	ar rcs libestream.a $(LIB_OBJS)

-include $(LIB_OBJS:.o=.d)

tests: $(TESTS)

%_test: libestream.a tests/%_test.o
	gcc $(CFLAGS) tests/$*_test.o libestream.a -o $*_test

%.o: %.c
	gcc -c $(CFLAGS) -I. $*.c -o $*.o
	gcc -MM $(CFLAGS) -I. $*.c > $*.d

clean:
	rm -f libestream.a *.o *.d tests/*.o tests/*.d $(TESTS)
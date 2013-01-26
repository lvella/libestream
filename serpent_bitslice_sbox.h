
/* Partially optimised Serpent S Box boolean functions derived  */
/* using a recursive descent analyser but without a full search */
/* of all subtrees. This set of S boxes is the result of work	*/
/* by Sam Simpson and Brian Gladman using the spare time on a	*/
/* cluster of high capacity servers to search for S boxes with	*/
/* this customised search engine. There are now an average of	*/
/* 15.375 terms	per S box.										*/
/*                                                              */
/* Copyright:   Dr B. R Gladman                                 */
/*				and Sam Simpson (s.simpson@mia.co.uk)			*/ 
/*              17th December 1998								*/
/*                                                              */
/* We hereby give permission for information in this file to be */
/* used freely subject only to acknowledgement of its origin.	*/

/* Found in:
http://gladman.plushost.co.uk/oldsite/cryptography_technology/serpent/index.php
*/

/* 15 terms */

#define sb0(a,b,c,d,e,f,g,h)	\
	t1 = a ^ d;		\
	t2 = a & d;		\
	t3 = c ^ t1;	\
	t4 = b ^ t3;	\
	h = t2 ^ t4;	\
	t6 = b & t1;	\
	t7 = a ^ t6;	\
	t8 = c | t7;	\
	g = t4 ^ t8;	\
	t10 = ~t3;		\
	t11 = t3 ^ t7;	\
	t12 = h & t11;	\
	f = t10 ^ t12;	\
	t14 = ~t7;		\
	e = t12 ^ t14

/* 14 terms  */

#define sb1(a,b,c,d,e,f,g,h)	\
	t1 = ~a;		\
	t2 = b ^ t1;	\
	t3 = a | t2;	\
	t4 = d | t2;	\
	t5 = c ^ t3;	\
	g = d ^ t5;		\
	t7 = b ^ t4;	\
	t8 = t2 ^ g;	\
	t9 = t5 & t7;	\
	h = t8 ^ t9;	\
	t11 = t5 ^ t7;	\
	f = h ^ t11;	\
	t13 = t8 & t11;	\
	e = t5 ^ t13

/* 16 terms */

#define sb2(a,b,c,d,e,f,g,h)	\
    t1 = ~a;		\
    t2 = b ^ d;     \
    t3 = c & t1;    \
    e = t2 ^ t3;    \
    t5 = c ^ t1;    \
    t6 = c ^ e;     \
    t7 = b & t6;    \
    h = t5 ^ t7;    \
    t9 = d | t7;    \
    t10 = e | t5;   \
    t11 = t9 & t10;	\
    g = a ^ t11;    \
    t13 = d | t1;   \
    t14 = t2 ^ h;   \
    t15 = g ^ t13;  \
    f = t14 ^ t15

/* 16 terms	*/

#define sb3(a,b,c,d,e,f,g,h)	\
	t1 = a ^ b;		\
	t2 = a & c;		\
	t3 = a | d;		\
	t4 = c ^ d;		\
	t5 = t1 & t3;	\
	t6 = t2 | t5;	\
	g = t4 ^ t6;	\
	t8 = b ^ t3;	\
	t9 = t6 ^ t8;	\
	t10 = t4 & t9;	\
	e = t1 ^ t10;	\
	t12 = g & e;	\
	f = t9 ^ t12;	\
	t14 = b | d;	\
	t15 = t4 ^ t12;	\
	h = t14 ^ t15

/* 15 terms	*/

#define sb4(a,b,c,d,e,f,g,h)	\
	t1 = a ^ d;		\
	t2 = d & t1;	\
	t3 = c ^ t2;	\
	t4 = b | t3;	\
	h = t1 ^ t4;	\
	t6 = ~b;		\
	t7 = t1 | t6;	\
	e = t3 ^ t7;	\
	t9 = a & e;		\
	t10 = t1 ^ t6;	\
	t11 = t4 & t10;	\
	g = t9 ^ t11;	\
	t13 = a ^ t3;	\
	t14 = t10 & g;	\
	f = t13 ^ t14

/* 16 terms	*/

#define sb5(a,b,c,d,e,f,g,h)	\
	t1 = ~a;		\
	t2 = a ^ b;		\
	t3 = a ^ d;		\
	t4 = c ^ t1;	\
	t5 = t2 | t3;	\
	e = t4 ^ t5;	\
	t7 = d & e;		\
	t8 = t2 ^ e;	\
	f = t7 ^ t8;	\
	t10 = t1 | e;	\
	t11 = t2 | t7;	\
	t12 = t3 ^ t10;	\
	g = t11 ^ t12;	\
	t14 = b ^ t7;	\
	t15 = f & t12;	\
	h = t14 ^ t15

/* 15 terms */

#define sb6(a,b,c,d,e,f,g,h)	\
	t1 = ~a;		\
	t2 = a ^ d;		\
	t3 = b ^ t2;	\
	t4 = t1 | t2;	\
	t5 = c ^ t4;	\
	f = b ^ t5;		\
	t7 = t2 | f;	\
	t8 = d ^ t7;	\
	t9 = t5 & t8;	\
	g = t3 ^ t9;	\
	t11 = t5 ^ t8;	\
	e = g ^ t11;	\
	t13 = ~t5;		\
	t14 = t3 & t11;	\
	h = t13 ^ t14

/* 16 terms */

#define sb7(a,b,c,d,e,f,g,h)	\
	t1 = b ^ c;		\
	t2 = c & t1;	\
	t3 = d ^ t2;	\
	t4 = a ^ t3;	\
	t5 = d | t1;	\
	t6 = t4 & t5;	\
	f = b ^ t6;		\
	t8 = t3 | f;	\
	t9 = a & t4;	\
	h = t1 ^ t9;	\
	t11 = t4 ^ t8;	\
	t12 = h & t11;	\
	g = t3 ^ t12;	\
	t14 = ~t11;		\
	t15 = h & g;	\
	e = t14 ^ t15

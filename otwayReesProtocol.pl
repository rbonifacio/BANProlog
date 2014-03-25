:- dynamic knows/2.

principal(a).
principal(b).
principal(server).

issue(server, sharedKey(a, b, kab)).

sharedKey(a, server, kas).
sharedKey(b, server, kbs).
sharedKey(server, a, kas).
sharedKey(server, b, kbs).


nonce(a, na).
nonce(b, nb).
nonce(a, nc).

knows(P, plainMessage(M)) :- knows(P,M).
knows(P, cipherMessage(K, CS)) :- sharedKey(P, _, K), knowsAll(P, CS).
knows(P, sharedKey(P1, P2, K)) :- issue(P, sharedKey(P1, P2, K)). 
knows(P,  M) :- nonce(P, M).

knowsAll(_, []).
knowsAll(P, [C|CS]) :- knows(P, C), knowsAll(P, CS).

canRead(_, plainMessage(_)).
canRead(P, cipherMessage(K, _)) :- principal(P), sharedKey(P, _, K); sharedKey(_, P, K).

 
runProtocol(P1, P2, AS, NC, NA, NB, MSS) :- 
 sharedKey(P1, AS, KAS), 
 sharedKey(P2, AS, KBS),
 issue(AS, sharedKey(P1, P2, KAB)),
 MSS = ([(P1, P2, [plainMessage(NC), cipherMessage(KAS, [NA, NC])])
	    , (P2, AS, [plainMessage(NC), cipherMessage(KAS, [NA, NC]), cipherMessage(KBS, [NB, NC])])
	    , (AS, P2, [plainMessage(NC), cipherMessage(KAS, [NA, sharedKey(P1, P2, KAB)]), cipherMessage(KBS, [NB, sharedKey(P1, P2, KAB)])])
	    , (P2, P1, [plainMessage(NC), cipherMessage(KAS, [NA, sharedKey(P1, P2, KAB)])])
	    ]).



verify(P1, P2, AS, NC, NA, NB, K) :- runProtocol(P1, P2, AS, NC, NA, NB, [M|MS]), 
                     verifyMessages([M|MS]),
                     knows(P1, sharedKey(P1, P2, K)), 
                     knows(P2, sharedKey(P1, P2, K)).

verifyMessages([]).
verifyMessages([(P1, P2, CS)|MS]) :- validMessage(P1, P2, CS),
                                     receiveMessages(P2, CS),
                                     verifyMessages(MS).

validMessage(P1, P2, CS) :- principal(P1), 
                            principal(P2), 
                            knowsAll(P1, CS).                             
receiveMessages(_, []).
receiveMessages(P, [M|MS]) :- receiveMessage(P, M), receiveMessages(P, MS).

receiveMessage(P, plainMessage(M)) :- asserta(knows(P,M)).
receiveMessage(P, cipherMessage(K, CS)) :- canRead(P, cipherMessage(K, CS)), disclosure(P, CS).
receiveMessage(P, cipherMessage(K, CS)) :- not(canRead(P, cipherMessage(K,CS))), asserta(knows(P, cipherMessage(K,CS))).

disclosure(P, [C|CS]) :- asserta(knows(P,C)), disclosure(P, CS).
disclosure(_, []).  
 

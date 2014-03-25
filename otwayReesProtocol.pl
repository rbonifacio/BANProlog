:- dynamic knows/2.
:- dynamic nonce/2.
:- dynamic sharedKey/3.

principal(a).
principal(b).
principal(server).

authorizationServer(server).

issue(AS, sharedKey(P1, P2, KAB)) :- 
 authorizationServer(AS), 
 principal(P1),
 principal(P2), 
 R is random(50), 
 atom_concat('k', R, KAB), 
 asserta(sharedKey(P1, P2, KAB)), 
 asserta(sharedKey(P2, P1, KAB)). 

sharedKey(a, server, kas).
sharedKey(b, server, kbs).
sharedKey(server, a, kas).
sharedKey(server, b, kbs).

/*
nonce(a, na).
nonce(b, nb).
nonce(a, nc).
*/
knows(P, plainMessage(M)) :- knows(P,M).
knows(P, cipherMessage(K, CS)) :- sharedKey(P, _, K), knowsAll(P, CS).
knows(P, sharedKey(P1, P2, K)) :- issue(P, sharedKey(P1, P2, K)). 
knows(P,  M) :- nonce(P, M).

knowsAll(_, []).

knowsAll(P, [C|CS]) :- knows(P, C), knowsAll(P, CS).

canRead(_, plainMessage(_)).
canRead(P, cipherMessage(K, _)) :- principal(P), sharedKey(P, _, K); sharedKey(_, P, K).

 
runProtocol(P1, P2) :- 
 NA is random(50),
 M is random(50),
 NC = (M, P1, P2), 
 asserta(nonce(P1, NA)), 
 asserta(nonce(P1, M)), 
 asserta(nonce(P1, NC)), 
 authorizationServer(AS),
 sharedKey(P1, AS, KAS), 
 sendMessage(m1(P1, P2, [plainMessage(NC), cipherMessage(KAS, [NA, NC])])).


sendMessage(M) :- receiveMessage(M).


receiveMessage(m1(_, P2, [C1, C2])) :- 
 NB is random(50),
 asserta(nonce(P2, NB)), 
 authorizationServer(AS),
 sharedKey(P2, AS, KBS), 
 sendMessage(m2(P2, AS, [C1, C2, cipherMessage(KBS, [NB, C1])])).

receiveMessage(m2(P2, AS, [C1, C2, C3])) :-
 plainMessage((M, P1, P2)) = C1,
 cipherMessage(KAS, C2Detail) = C2, 
 sharedKey(AS, P1, KAS),
 [NA, (M, P1, P2)] = C2Detail, 
 nonce(P1, NA),
 nonce(P1, (M, P1, P2)),
 cipherMessage(KBS, C3Detail) = C3, 
 sharedKey(AS, P2, KBS), 
 [NB, C1] = C3Detail, 
 nonce(P2, NB), 
 issue(AS, sharedKey(P1, P2, KAB)),
 sendMessage(m3(AS, P2, [C1, cipherMessage(KAS, [C1, sharedKey(P1, P2, KAB)]), cipherMessage(KBS, [C1, sharedKey(P1, P2, KAB)])])).

receiveMessage(m3(AS, P2, [C1, C2, C3])) :- 
 plainMessage((M, P1, P2)) = C1, 
 nonce(P1, M), 
 cipherMessage(KBS, C3Detail) = C3, 
 authorizationServer(AS), 
 sharedKey(P2, AS, KBS), 
 [C1, sharedKey(P1, P2, KAB)] = C3Detail, 
 sharedKey(P1, P2, KAB),
 asserta(knows(P2, sharedKey(P1, P2, KAB))), 
 sendMessage(m4(P2, P1, [C1, C2])).  

receiveMessage(m4(P2, P1, [C1, C2])) :- 
 plainMessage((M, P1, P2)) = C1,
 nonce(P1, M),
 cipherMessage(KAS, C2Detail) = C2, 
 authorizationServer(AS),
 sharedKey(P1, AS, KAS), 
 [C1, sharedKey(P1, P2, KAB)] = C2Detail, 
 sharedKey(P1, P2, KAB), 
 asserta(knows(P1, sharedKey(P1, P2, KAB))). 


verify(P1, P2, K) :- runProtocol(P1, P2), 
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
 

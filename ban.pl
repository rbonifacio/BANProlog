:- op(1200, xfx, if).
:- op(1000, xfx, and).
:- op(900, xfx, &). 

postulate(believes(P, onceSaid(Q, X)) if believes(P, sharedKey(P, Q, K)) and sees(P, cipherMessage(X, K))).
postulate(believes(P, onceSaid(Q, X)) if believes(P, publicKey(Q, K)) and sees(P, cipherMessage(X, privateKey(K))))
postulate(believes(P, onceSaid(Q, X)) if believes(P, sharedSecret(P, Q, Y)) and sees(P, messageWithSecret(X, Y)))
postulate(believes(P, believes(Q, X)) if believes(P, nonce(X)) and said(Q, X))
postulate(believes(P, X) if believes(P, hasJurisdiction(Q, X)) and believes(P, believes(Q, X)))


solve(true, void).
solve((X and Y), (Px & Py)) :- solve(X, Px), solve(Y, Py).
solve(X, proof(X, Py)) :- postulate(X if Y), solve(Y, Py).


canRead(_, plainMessage(_)).
canRead(P, cipherMessage(K, _)) :- principal(P), sharedKey(P, _, K); sharedKey(_, P, K).
 



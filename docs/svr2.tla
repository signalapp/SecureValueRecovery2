---------------------------- MODULE svr2 ----------------------------
\*
\* Based on is the formal specification for the Raft consensus algorithm 
\* (Diego Ongaro, 2014) which is licensed under the Creative Commons Attribution-4.0
\* International License https://creativecommons.org/licenses/by/4.0/

EXTENDS Naturals, FiniteSets, Sequences, TLC, Randomization

\* The set of server IDs
CONSTANTS Server

\* The set of IDs of servers that are rolled back
CONSTANTS RollbackServer

\* Server states.
CONSTANTS Follower, Candidate, Leader

\* A reserved value.
CONSTANTS Nil

\* Message types:
CONSTANTS RequestVoteRequest, RequestVoteResponse,
          AppendEntriesRequest, AppendEntriesResponse
          
\* Maximum number of client requests
CONSTANTS MaxClientRequests

CONSTANTS MaxSteps

CONSTANTS RollbackTolerance




----
\* Global variables


\* A bag of records representing requests and responses sent from one server
\* to another. TLAPS doesn't support the Bags module, so this is a function
\* mapping Message to Nat.
VARIABLE messages

\* A history variable used in the proof. This would not be present in an
\* implementation.
\* Keeps track of successful elections, including the initial logs of the
\* leader and voters' logs. Set of functions containing various things about
\* successful elections (see BecomeLeader).
VARIABLE elections

\* A history variable used in the proof. This would not be present in an
\* implementation.
\* Keeps track of every log ever in the system (set of logs).
VARIABLE allLogs


\* a step counter used to model Rollback
VARIABLE step

\* a map from Server to a sequence of server states - one for each step.
VARIABLE serverStates

\* A hash function used to compute a hash chain
VARIABLE hash

----
\* The following variables are all per server (functions with domain Server).

\* The server's term number.
VARIABLE currentTerm
\* The server's state (Follower, Candidate, or Leader).
VARIABLE state
\* The candidate the server voted for in its current term, or
\* Nil if it hasn't voted for any.
VARIABLE votedFor
serverVars == <<currentTerm, state, votedFor>>

\* The set of requests that can go into the log
VARIABLE clientRequests

\* A Sequence of log entries. The index into this sequence is the index of the
\* log entry. Unfortunately, the Sequence module defines Head(s) as the entry
\* with index 1, so be careful not to use that!
VARIABLE log
\* The latest entry that each follower has promised the leader to commit.
\* This is used to calculate commitIndex on the leader.
VARIABLE promiseIndex
\* The index of the latest entry in the log the state machine may apply.
VARIABLE commitIndex
VARIABLE promisedLog
VARIABLE promisedLogDecrease
\* The index that gets committed
VARIABLE committedLog
\* Does the commited Index decrease
VARIABLE committedLogDecrease
logVars == <<log, commitIndex, promiseIndex, clientRequests, committedLog, committedLogDecrease, promisedLog, promisedLogDecrease >>

\* The following variables are used only on candidates:
\* The set of servers from which the candidate has received a RequestVote
\* response in its currentTerm.
VARIABLE votesSent
\* The set of servers from which the candidate has received a vote in its
\* currentTerm.
VARIABLE votesGranted
\* A history variable used in the proof. This would not be present in an
\* implementation.
\* Function from each server that voted for this candidate in its currentTerm
\* to that voter's log.
VARIABLE voterLog
candidateVars == <<votesSent, votesGranted, voterLog>>

\* The following variables are used only on leaders:
\* The next entry to send to each follower.
VARIABLE nextIndex
\* The latest entry that each follower has acknowledged is the same as the
\* leader's. This is used to calculate promiseIndex on the leader.
VARIABLE matchIndex
VARIABLE ackedPromiseIndex
leaderVars == <<nextIndex, matchIndex, ackedPromiseIndex, elections>>

\* End of per server variables.
----

\* All variables; used for stuttering (asserting state hasn't changed).
vars == <<messages, allLogs, serverVars, candidateVars, leaderVars, logVars, hash, serverStates, step>>

\* Hash function setup

BitString256 == [1..256 -> BOOLEAN]
----
\* Helpers

\* The set of all quorums. This just calculates simple majorities, but the only
\* important property is that every quorum overlaps with every other.
Quorum == {i \in SUBSET(Server) : Cardinality(i) * 2 > RollbackTolerance + Cardinality(Server)}

\* The term of the last entry in a log, or 0 if the log is empty.
LastTerm(xlog) == IF Len(xlog) = 0 THEN 0 ELSE xlog[Len(xlog)].term

\* Helper for Send and Reply. Given a message m and bag of messages, return a
\* new bag of messages with one more m in it.
WithMessage(m, msgs) ==
    IF m \in DOMAIN msgs THEN
        [msgs EXCEPT ![m] = IF msgs[m] < 2 THEN msgs[m] + 1 ELSE 2 ]
    ELSE
        msgs @@ (m :> 1)

\* Helper for Discard and Reply. Given a message m and bag of messages, return
\* a new bag of messages with one less m in it.
WithoutMessage(m, msgs) ==
    IF m \in DOMAIN msgs THEN
        [msgs EXCEPT ![m] = IF msgs[m] > 0 THEN msgs[m] - 1 ELSE 0 ]
    ELSE
        msgs
        
ValidMessage(msgs) ==
    { m \in DOMAIN messages : msgs[m] > 0 }
    
SingleMessage(msgs) ==
    { m \in DOMAIN messages : msgs[m] = 1 } 

\* Add a message to the bag of messages.
Send(m) == messages' = WithMessage(m, messages)

\* Remove a message from the bag of messages. Used when a server is done
\* processing a message.
Discard(m) == messages' = WithoutMessage(m, messages)

\* Combination of Send and Discard
Reply(response, request) ==
    messages' = WithoutMessage(request, WithMessage(response, messages))

\* Return the minimum value from a set, or undefined if the set is empty.
Min(s) == CHOOSE x \in s : \A y \in s : x <= y
\* Return the maximum value from a set, or undefined if the set is empty.
Max(s) == CHOOSE x \in s : \A y \in s : x >= y

\* The current state of server i
CurrentFollowerState(i) == [
                           sslog |-> log[i],
                           sscurrentTerm |-> currentTerm[i],
                           ssvotedFor |-> votedFor[i],
                           ssstate |-> state[i],
                           sspromiseIndex |-> promiseIndex[i],
                           sscommitIndex |-> commitIndex[i]]
CurrentLeaderState(i) == [
                           sslog |-> log[i],
                           sscurrentTerm |-> currentTerm[i],
                           ssvotedFor |-> votedFor[i],
                           ssstate |-> state[i],
                           sspromiseIndex |-> promiseIndex[i],
                           sscommitIndex |-> commitIndex[i],
                           ssnextIndex |-> nextIndex[i],
                           ssmatchIndex |-> matchIndex[i],
                           ssackedPromiseIndex |-> ackedPromiseIndex[i]]
CurrentCandidateState(i) == [
                           sslog |-> log[i],
                           sscurrentTerm |-> currentTerm[i],
                           ssvotedFor |-> votedFor[i],
                           ssstate |-> state[i],
                           sspromiseIndex |-> promiseIndex[i],
                           sscommitIndex |-> commitIndex[i],
                           ssvotesSent |-> votesSent[i],
                           ssvotesGranted |-> votesGranted[i]]

CurrentState(i) == IF state[i] = Follower THEN CurrentFollowerState(i)
                   ELSE IF state[i] = Candidate THEN CurrentCandidateState(i)
                   ELSE CurrentLeaderState(i)

RecordStates == LET currentState == [i \in Server |-> CurrentState(i)]
                  IN serverStates' = [serverStates EXCEPT ![step] = currentState]


----
\* Define initial values for all variables

InitHistoryVars == /\ elections = {}
                   /\ allLogs   = {}
                   /\ voterLog  = [i \in Server |-> [j \in {} |-> <<>>]]
                   /\ serverStates = [s \in 0..MaxSteps |-> [i \in Server |-> <<>>]]
InitServerVars == /\ currentTerm = [i \in Server |-> 1]
                  /\ state       = [i \in Server |-> Follower]
                  /\ votedFor    = [i \in Server |-> Nil]
InitCandidateVars == /\ votesSent = [i \in Server |-> FALSE ]
                     /\ votesGranted   = [i \in Server |-> {}]
\* The values nextIndex[i][i] and matchIndex[i][i] are never read, since the
\* leader does not send itself messages. It's still easier to include these
\* in the functions.
InitLeaderVars == /\ nextIndex  = [i \in Server |-> [j \in Server |-> 1]]
                  /\ matchIndex = [i \in Server |-> [j \in Server |-> 0]]
                  /\ ackedPromiseIndex = [i \in Server |-> [j \in Server |-> 0]]

InitLogVars == /\ log          = [i \in Server |-> << >>]
               /\ commitIndex  = [i \in Server |-> 0]
               /\ promiseIndex  = [i \in Server |-> 0]
               /\ clientRequests = 1
               /\ committedLog = << >>
               /\ committedLogDecrease = FALSE
               /\ promisedLog = << >>
               /\ promisedLogDecrease = FALSE    

RollbackServersAreServers ==
    /\ IsFiniteSet(RollbackServer)
    /\ RollbackServer \subseteq Server
     
Init == /\ messages = [m \in {} |-> 0]
        /\ InitHistoryVars
        /\ InitServerVars
        /\ InitCandidateVars
        /\ InitLeaderVars
        /\ InitLogVars
        /\ step = 0
        /\ hash = [x \in {} |-> Nil]
        /\ RollbackServersAreServers

----
\* Define state transitions

\* Server i times out and starts a new election.
Timeout(i) == /\ state[i] \in {Follower, Candidate}
              /\ state' = [state EXCEPT ![i] = Candidate]
              /\ currentTerm' = [currentTerm EXCEPT ![i] = currentTerm[i] + 1]
              \* Most implementations would probably just set the local vote
              \* atomically, but messaging localhost for it is weaker.
              /\ votedFor' = [votedFor EXCEPT ![i] = Nil]
              /\ votesSent' = [votesSent EXCEPT ![i] = FALSE ]
              /\ votesGranted'   = [votesGranted EXCEPT ![i] = {}]
              /\ voterLog'       = [voterLog EXCEPT ![i] = [j \in {} |-> <<>>]]
              /\ UNCHANGED <<messages, leaderVars, logVars, hash>>

\* Rollback server i to its state at step s
Rollback(i, s) == LET restoreState == serverStates[s][i]
    IN  /\ i \in RollbackServer
        /\ log' = [log EXCEPT ![i] = restoreState.sslog]
        /\ currentTerm' = [currentTerm EXCEPT ![i] = restoreState.sscurrentTerm]
        /\ votedFor' = [votedFor EXCEPT ![i] = restoreState.ssvotedFor]
        /\ state' = [state EXCEPT ![i] = restoreState.ssstate]
        /\ promiseIndex' = [promiseIndex EXCEPT ![i] = restoreState.sspromiseIndex]
        /\ commitIndex' = [commitIndex EXCEPT ![i] = restoreState.sscommitIndex]
        /\ \/ /\ restoreState.ssstate = Follower
           \/ /\ restoreState.ssstate = Candidate
              /\ votesSent' = [votesSent EXCEPT ![i] = restoreState.ssvotesSent]
              /\ votesGranted' = [votesGranted EXCEPT ![i] = restoreState.ssvotesGranted]
           \/ /\ restoreState.ssstate = Leader
              /\ nextIndex' = [nextIndex EXCEPT ![i] = restoreState.ssnextIndex]
              /\ matchIndex' = [matchIndex EXCEPT ![i] = restoreState.ssmatchIndex]
              /\ ackedPromiseIndex' = [ackedPromiseIndex EXCEPT ![i] = restoreState.ssackedPromiseIndex]
        /\ UNCHANGED <<messages, elections, clientRequests, committedLog, committedLogDecrease, promisedLog, promisedLogDecrease, ackedPromiseIndex, matchIndex, nextIndex, voterLog, votesGranted, votesSent, hash >>

\* Candidate i sends j a RequestVote request.
RequestVote(i,j) ==
    /\ state[i] = Candidate
    /\ Send([mtype         |-> RequestVoteRequest,
             mterm         |-> currentTerm[i],
             mlastLogTerm  |-> LastTerm(log[i]),
             mlastLogIndex |-> Len(log[i]),
             msource       |-> i,
             mdest         |-> j])
    /\ UNCHANGED <<serverVars, votesGranted, voterLog, leaderVars, logVars, votesSent, hash>>

\* Leader i sends j an AppendEntries request containing up to 1 entry.
\* While implementations may want to send more than 1 at a time, this spec uses
\* just 1 because it minimizes atomic regions without loss of generality.
AppendEntries(i, j) ==
    /\ i /= j
    /\ state[i] = Leader
    /\ LET prevLogIndex == nextIndex[i][j] - 1
           prevLogTerm == IF prevLogIndex > 0 THEN
                              log[i][prevLogIndex].term
                          ELSE
                              0
           prevLogHash == IF prevLogIndex > 0 THEN
                              log[i][prevLogIndex].hashChain
                          ELSE
                              0
           \* Send up to 1 entry, constrained by the end of the log.
           lastEntry == Min({Len(log[i]), nextIndex[i][j]})
           entries == SubSeq(log[i], nextIndex[i][j], lastEntry)
       IN Send([mtype          |-> AppendEntriesRequest,
                mterm          |-> currentTerm[i],
                mprevLogIndex  |-> prevLogIndex,
                mprevLogTerm   |-> prevLogTerm,
                mprevLogHash   |-> prevLogHash,
                mentries       |-> entries,
                \* mlog is used as a history variable for the proof.
                \* It would not exist in a real implementation.
                mlog           |-> log[i],
                mcommitIndex   |-> Min({commitIndex[i], lastEntry}),
                mpromiseIndex  |-> Min({promiseIndex[i], lastEntry}),
                msource        |-> i,
                mdest          |-> j])
    /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars, hash>>

\* Candidate i transitions to leader.
BecomeLeader(i) ==
    /\ state[i] = Candidate
    /\ votesGranted[i] \in Quorum
    /\ state'      = [state EXCEPT ![i] = Leader]
    /\ nextIndex'  = [nextIndex EXCEPT ![i] =
                         [j \in Server |-> Len(log[i]) + 1]]
    /\ matchIndex' = [matchIndex EXCEPT ![i] =
                         [j \in Server |-> 0]]
    /\ ackedPromiseIndex' = [ackedPromiseIndex EXCEPT ![i] =
                         [j \in Server |-> 0]]
    /\ elections'  = elections \cup
                         {[eterm     |-> currentTerm[i],
                           eleader   |-> i,
                           elog      |-> log[i],
                           evotes    |-> votesGranted[i],
                           evoterLog |-> voterLog[i],
                           estep     |-> step]}
    /\ UNCHANGED <<messages, currentTerm, votedFor, candidateVars, logVars, hash>>

\* Leader i receives a client request to add v to the log.
ClientRequest(i) ==
    /\ state[i] = Leader
    /\ clientRequests < MaxClientRequests
    /\ LET index == Len(log[i])
           hashInput == [ hiindex |-> index, hiterm |-> currentTerm[i], hivalue |-> clientRequests, hilastHash |-> log[i][Len(log[i])] ]
           hashValue == IF [ hiindex |-> index, hiterm |-> currentTerm[i], hivalue |-> clientRequests, hilastHash |-> log[i][Len(log[i])] ] \in DOMAIN hash THEN
                           hash[[ hiindex |-> index, hiterm |-> currentTerm[i], hivalue |-> clientRequests, hilastHash |-> log[i][Len(log[i])] ]]
                       ELSE
                            RandomElement(BitString256)
           entry == [term  |-> currentTerm[i],
                     hashChain |-> hash[hashInput],
                     value |-> clientRequests]
           newLog == Append(log[i], entry)
       IN  /\ log' = [log EXCEPT ![i] = newLog]
           \* Make sure that each request is unique, reduce state space to be explored
           /\ clientRequests' = clientRequests + 1
           /\ hash' = [hash EXCEPT ![hashInput] = hashValue]
    /\ UNCHANGED <<messages, serverVars, candidateVars,
                   leaderVars, commitIndex, promiseIndex, committedLog, committedLogDecrease, promisedLog, promisedLogDecrease>>

\* Leader i advances its promiseIndex.
\* This is done as a separate step from handling AppendEntries responses,
\* in part to minimize atomic regions, and in part so that leaders of
\* single-server clusters are able to mark entries committed.
AdvancePromiseIndex(i) ==
    /\ state[i] = Leader
    /\ LET \* The set of servers that agree up through index.
           Agree(index) == {i} \cup {k \in Server :
                                         matchIndex[i][k] >= index}
           \* The maximum indexes for which a quorum agrees
           agreeIndexes == {index \in 1..Len(log[i]) :
                                Agree(index) \in Quorum}
           \* New value for commitIndex'[i]
           newPromiseIndex ==
              IF /\ agreeIndexes /= {}
                 /\ log[i][Max(agreeIndexes)].term = currentTerm[i]
              THEN
                  Max(agreeIndexes \cup {promiseIndex[i]})
              ELSE
                  promiseIndex[i]
           newPromisedLog ==
              IF newPromiseIndex > 1 THEN 
                  [ j \in 1..newPromiseIndex |-> log[i][j] ] 
              ELSE 
                   << >>
       IN /\ promiseIndex' = [promiseIndex EXCEPT ![i] = newPromiseIndex]
          /\ promisedLogDecrease' = \/ ( newPromiseIndex < Len(promisedLog) )
                                     \/ \E j \in 1..Len(promisedLog) : promisedLog[j] /= newPromisedLog[j]
          /\ promisedLog' = newPromisedLog
    /\ UNCHANGED <<messages, serverVars, candidateVars, leaderVars, log, clientRequests, commitIndex, committedLog, committedLogDecrease, hash>>


\* Leader i advances its commitIndex.
\* This is done as a separate step from handling AppendEntries responses,
\* in part to minimize atomic regions, and in part so that leaders of
\* single-server clusters are able to mark entries committed.
AdvanceCommitIndex(i) ==
    /\ state[i] = Leader
    /\ LET \* The set of servers that agree up through index.
           Agree(index) == {i} \cup {k \in Server :
                                         ackedPromiseIndex[i][k] >= index}
           \* The maximum indexes for which a quorum agrees
           agreeIndexes == {index \in 1..Len(log[i]) :
                                Agree(index) \in Quorum}
           \* New value for commitIndex'[i]
           newCommitIndex ==
              IF /\ agreeIndexes /= {}
                 /\ log[i][Max(agreeIndexes)].term = currentTerm[i]
              THEN
                  Max(agreeIndexes)
              ELSE
                  commitIndex[i]
           newCommittedLog ==
              IF newCommitIndex > 1 THEN 
                  [ j \in 1..newCommitIndex |-> log[i][j] ] 
              ELSE 
                   << >>
       IN /\ commitIndex' = [commitIndex EXCEPT ![i] = newCommitIndex]
          /\ committedLogDecrease' = \/ ( newCommitIndex < Len(committedLog) )
                                     \/ \E j \in 1..Len(committedLog) : committedLog[j] /= newCommittedLog[j]
          /\ committedLog' = newCommittedLog
    /\ UNCHANGED <<messages, serverVars, candidateVars, leaderVars, log, clientRequests, promiseIndex, promisedLog, promisedLogDecrease, hash>>


----
\* Message handlers
\* i = recipient, j = sender, m = message

\* Server i receives a RequestVote request from server j with
\* m.mterm <= currentTerm[i].
HandleRequestVoteRequest(i, j, m) ==
    LET logOk == \/ m.mlastLogTerm > LastTerm(log[i])
                 \/ /\ m.mlastLogTerm = LastTerm(log[i])
                    /\ m.mlastLogIndex >= Len(log[i])
        grant == /\ m.mterm = currentTerm[i]
                 /\ logOk
                 /\ votedFor[i] \in {Nil, j}
    IN /\ m.mterm <= currentTerm[i]
       /\ \/ grant  /\ votedFor' = [votedFor EXCEPT ![i] = j]
          \/ ~grant /\ UNCHANGED votedFor
       /\ Reply([mtype        |-> RequestVoteResponse,
                 mterm        |-> currentTerm[i],
                 mvoteGranted |-> grant,
                 \* mlog is used just for the `elections' history variable for
                 \* the proof. It would not exist in a real implementation.
                 mlog         |-> log[i],
                 msource      |-> i,
                 mdest        |-> j],
                 m)
       /\ UNCHANGED <<state, currentTerm, candidateVars, leaderVars, logVars, hash>>

\* Server i receives a RequestVote response from server j with
\* m.mterm = currentTerm[i].
HandleRequestVoteResponse(i, j, m) ==
    \* This tallies votes even when the current state is not Candidate, but
    \* they won't be looked at, so it doesn't matter.
    /\ m.mterm = currentTerm[i]
    /\ \/ /\ m.mvoteGranted
          /\ votesGranted' = [votesGranted EXCEPT ![i] =
                                  votesGranted[i] \cup {j}]
          /\ voterLog' = [voterLog EXCEPT ![i] =
                              voterLog[i] @@ (j :> m.mlog)]
          /\ UNCHANGED <<votesSent>>
       \/ /\ ~m.mvoteGranted
          /\ UNCHANGED <<votesSent, votesGranted, voterLog>>
    /\ Discard(m)
    /\ UNCHANGED <<serverVars, votedFor, leaderVars, logVars, hash>>

\* Server i receives an AppendEntries request from server j with
\* m.mterm <= currentTerm[i]. This just handles m.entries of length 0 or 1, but
\* implementations could safely accept more by treating them the same as
\* multiple independent requests of 1 entry.
HandleAppendEntriesRequest(i, j, m) ==
    LET hashInput == [hiindex |-> m.mprevLogIndex+1, 
                     hiterm |-> m.mentries[1].term, 
                     hivalue |-> m.mentries[1].value, 
                     hilastHash |-> log[i][m.mprevLogIndex].hashChain]
          hashValue == IF hashInput \in DOMAIN hash THEN
                           hash[hashInput]
                       ELSE 
                           RandomElement(BitString256)
          logOk == \/ m.mprevLogIndex = 0
                 \/ /\ m.mprevLogIndex > 0
                    /\ m.mprevLogIndex <= Len(log[i])
                    /\ m.mprevLogTerm = log[i][m.mprevLogIndex].term
                    /\ m.mprevLogHash = log[i][m.mprevLogIndex].hashChain
                    /\ \/ /\ Len(m.mentries) = 0
                          /\ UNCHANGED hash
                       \/ /\ m.mprevLogIndex < Len(log[i])
                          /\ UNCHANGED hash
                          /\ \/ m.mentries[1].hashChain = log[i][m.mprevLogIndex+1].hashChain
                             \/ \* there's a conflict on a non-promised entry
                                /\ Len(m.mentries) > 0
                                /\ log[i][m.mprevLogIndex+1].term /= m.mentries[1].term
                                /\ promiseIndex[i] < Len(log[i])
                       \/ /\ m.mprevLogIndex = Len(log[i])
                          /\ m.mentries[1].hashChain = hashValue
                          /\ hash' = [hash EXCEPT ![hashInput] = hashValue]
    IN /\ m.mterm <= currentTerm[i]
       /\ \/ /\ \* reject request
                \/ m.mterm < currentTerm[i]
                \/ /\ m.mterm = currentTerm[i]
                   /\ state[i] = Follower
                   /\ \lnot logOk
             /\ Reply([mtype           |-> AppendEntriesResponse,
                       mterm           |-> currentTerm[i],
                       msuccess        |-> FALSE,
                       mackedPromiseIndex |-> 0,
                       mmatchIndex     |-> 0,
                       msource         |-> i,
                       mdest           |-> j],
                       m)
             /\ UNCHANGED <<serverVars, logVars>>
          \/ \* return to follower state
             /\ m.mterm = currentTerm[i]
             /\ state[i] = Candidate
             /\ state' = [state EXCEPT ![i] = Follower]
             /\ UNCHANGED <<currentTerm, votedFor, logVars, messages>>
          \/ \* accept request
             /\ m.mterm = currentTerm[i]
             /\ state[i] = Follower
             /\ logOk
             /\ LET index == m.mprevLogIndex + 1
                IN \/ \* already done with request
                       /\ \/ m.mentries = << >>
                          \/ /\ m.mentries /= << >>
                             /\ Len(log[i]) >= index
                             /\ log[i][index].term = m.mentries[1].term
                          \* This could make our commitIndex decrease (for
                          \* example if we process an old, duplicated request),
                          \* but that doesn't really affect anything.
                       /\ commitIndex' = [commitIndex EXCEPT ![i] =
                                              m.mcommitIndex]
                       /\ promiseIndex' = [promiseIndex EXCEPT ![i] = 
                                              Max({m.mpromiseIndex, promiseIndex[i]})]
                       /\ Reply([mtype           |-> AppendEntriesResponse,
                                 mterm           |-> currentTerm[i],
                                 msuccess        |-> TRUE,
                                 mmatchIndex     |-> m.mprevLogIndex +
                                                     Len(m.mentries),
                                 mmatchHash      |-> log[i][m.mprevLogIndex + Len(m.mentries)].hashChain,
                                 mpromiseIndex   |-> m.mpromiseIndex,
                                 msource         |-> i,
                                 mdest           |-> j],
                                 m)
                       /\ UNCHANGED <<serverVars, log, clientRequests, committedLog, promisedLog, committedLogDecrease, promisedLogDecrease>>
                   \/ \* conflict: remove 1 entry
                       /\ m.mentries /= << >>
                       /\ Len(log[i]) >= index
                       /\ log[i][index].term /= m.mentries[1].term
                       /\ promiseIndex[i] < Len(log[i])
                       /\ LET new == [index2 \in 1..(Len(log[i]) - 1) |->
                                          log[i][index2]]
                          IN log' = [log EXCEPT ![i] = new]
                       /\ UNCHANGED <<serverVars, commitIndex, promiseIndex,messages, clientRequests, committedLog, committedLogDecrease, promisedLog, promisedLogDecrease>>
                   \/ \* no conflict: append entry
                       /\ m.mentries /= << >>
                       /\ Len(log[i]) = m.mprevLogIndex
                       /\ log' = [log EXCEPT ![i] =
                                      Append(log[i], m.mentries[1])]
                       /\ UNCHANGED <<serverVars, commitIndex, promiseIndex, messages, clientRequests, committedLog, committedLogDecrease, promisedLog, promisedLogDecrease>>
       /\ UNCHANGED <<candidateVars, leaderVars>>

\* Server i receives an AppendEntries response from server j with
\* m.mterm = currentTerm[i].
HandleAppendEntriesResponse(i, j, m) ==
    /\ m.mterm = currentTerm[i]
    /\ \/ /\ m.msuccess \* successful
          /\ m.mmatchHash = log[i][m.mmatchIndex].hashChain
          /\ nextIndex'  = [nextIndex  EXCEPT ![i][j] = m.mmatchIndex + 1]
          /\ matchIndex' = [matchIndex EXCEPT ![i][j] = m.mmatchIndex]
          /\ ackedPromiseIndex' = [ackedPromiseIndex EXCEPT ![i][j] = m.mpromiseIndex] 
       \/ /\ \lnot m.msuccess \* not successful
          /\ nextIndex' = [nextIndex EXCEPT ![i][j] =
                               Max({nextIndex[i][j] - 1, 1})]
          /\ UNCHANGED <<matchIndex>>
    /\ Discard(m)
    /\ UNCHANGED <<serverVars, candidateVars, logVars, elections, hash>>

\* Any RPC with a newer term causes the recipient to advance its term first.
UpdateTerm(i, j, m) ==
    /\ m.mterm > currentTerm[i]
    /\ currentTerm'    = [currentTerm EXCEPT ![i] = m.mterm]
    /\ state'          = [state       EXCEPT ![i] = Follower]
    /\ votedFor'       = [votedFor    EXCEPT ![i] = Nil]
       \* messages is unchanged so m can be processed further.
    /\ UNCHANGED <<messages, candidateVars, leaderVars, logVars, hash>>

\* Responses with stale terms are ignored.
DropStaleResponse(i, j, m) ==
    /\ m.mterm < currentTerm[i]
    /\ Discard(m)
    /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars, hash>>

\* Receive a message.
Receive(m) ==
    LET i == m.mdest
        j == m.msource
    IN \* Any RPC with a newer term causes the recipient to advance
       \* its term first. Responses with stale terms are ignored.
       \/ UpdateTerm(i, j, m)
       \/ /\ m.mtype = RequestVoteRequest
          /\ HandleRequestVoteRequest(i, j, m)
       \/ /\ m.mtype = RequestVoteResponse
          /\ \/ DropStaleResponse(i, j, m)
             \/ HandleRequestVoteResponse(i, j, m)
       \/ /\ m.mtype = AppendEntriesRequest
          /\ HandleAppendEntriesRequest(i, j, m)
       \/ /\ m.mtype = AppendEntriesResponse
          /\ \/ DropStaleResponse(i, j, m)
             \/ HandleAppendEntriesResponse(i, j, m)

\* End of message handlers.
----
\* Network state transitions

\* The network duplicates a message
DuplicateMessage(m) ==
    /\ Send(m)
    /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars, hash>>

\* The network drops a message
DropMessage(m) ==
    /\ Discard(m)
    /\ UNCHANGED <<serverVars, candidateVars, leaderVars, logVars, hash>>

----
\* Defines how the variables may transition.
Next == /\ \/ \E i \in Server : Timeout(i)
           \/ \E i, j \in Server : RequestVote(i, j)
           \/ \E i \in Server : BecomeLeader(i)
           \/ \E i \in Server : ClientRequest(i)
           \/ \E i \in Server : AdvancePromiseIndex(i)
           \/ \E i \in Server : AdvanceCommitIndex(i)
           \/ \E i,j \in Server : AppendEntries(i, j)
           \/ \E i \in Server : \E s \in 1..(step-1) : Rollback(i,s) 
           \/ \E m \in ValidMessage(messages) : Receive(m)
           \/ \E m \in SingleMessage(messages) : DuplicateMessage(m)
           \/ \E m \in ValidMessage(messages) : DropMessage(m)
           \* History variable that tracks every log ever:
        /\ allLogs' = allLogs \cup {log[i] : i \in Server}
        /\ RecordStates
        /\ step' = step + 1

\* The specification must start with the initial state and transition according
\* to Next.
Spec == Init /\ [][Next]_vars

    
 

=============================================================================
\* Modification History
\* Last modified Thu Oct 05 16:26:40 MDT 2023 by rolfe
\* Created Thu Jan 26 12:43:23 MST 2023 by rolfe

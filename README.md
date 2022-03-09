# Attention

the code is a proof of concept! It should only be used for
demonstration purposes and should only be used in a laboratory environment.
This proof of concept is not designed to interact with third-party systems, so
the consent of the owner of the systems used must be obtained before the proof
of concept is executed. Liability for any damage arising from the use of this
code is excluded.  **Run this code only at your own risk.**

## About this code
I recently had a discussion with a colleague about side channels in IP
communications. We considered how to hide short information in an ICMP packet
(Ping). One possibility might be the Time to Live of the packet.

In this approach, however, the length of the user data was chosen instead of
the Time to Live in order to transport information unobtrusively. Each of
the ping packets is filled with random data corresponding to the ASCII 
position.

1. How do you design and implement your RDP header and header fields?
   Do you use any additional header fields?

   RDP header include: magic number, type, sequence, window, where type
   indicate different packet type.

   Additional header fields: number, info, type.

2. How do you design and implement the connection management using SYN,
   FIN and RST packets? How to choose the initial sequence number?

   Like TCP connections, before connect will have SYN packets, before close
   will have FIN packets. And when error happened, RST packet will be need. 

   The initial sequence number can be 0.

3. How do you design and implement the flow control using window size?
   How to choose the initial window size and adjust the size?

   Like TCP window size control the flow. We can choose a window size to
   receive packets, when in window size the packets can be received normally.

   The initial window size can be 1024, and adjust by the packet size.

4. How do you design and implement the error detection, notification and
recovery? How to use timer? How many timers do you use? How to repsond to the
events at the sender and receiver side, respectively? How to ensure reliable
data transfer?

    Error detection: sequence number not continous. Recovery: packet resend agagin.

    Timers: 2 timer, recevier timer and send timer. Reliable data transfer
    should be based on the same sequence.

5. Any additional desin and implementation considerations you want to get
feedback from your lab insturctor?

    No consideration for now.

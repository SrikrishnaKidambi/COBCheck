IDENTIFICATION DIVISION.
       PROGRAM-ID. PROGA.

       ENVIRONMENT DIVISION.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT CUSTFILE ASSIGN TO 'CUSTFILE'
               ORGANIZATION IS INDEXED
               ACCESS MODE  IS RANDOM
               RECORD KEY   IS CUST-ID.

       DATA DIVISION.
       FILE SECTION.
       FD  CUSTFILE.
       01  CUSTFILE-REC.
           05  CF-CUST-ID          PIC 9(10).

       WORKING-STORAGE SECTION.
       01  WS-RETURN-CODE          PIC 9(04) VALUE ZEROS.
       01  WS-AUDIT-REC. 
           05  WS-AUDIT-SSN        PIC 9(09).
           05  WS-AUDIT-NAME       PIC X(25).
           05  WS-AUDIT-ACTION     PIC X(10).
       01  WS-DISPLAY-LINE         PIC X(80).
       01  CUSTOMER-RECORD.
           05  CUST-ID             PIC 9(10).
           05  CUST-FIRST-NAME     PIC X(25).
           05  CUST-LAST-NAME      PIC X(25).
           05  CUST-SSN            PIC 9(09).
           05  CUST-DOB            PIC X(10).
           05  CUST-ADDR-LINE-1    PIC X(50).
           05  CUST-ADDR-LINE-2    PIC X(50).
           05  CUST-EMAIL          PIC X(50).
           05  CUST-PHONE          PIC X(15).
           05  CUST-CARD-NUM       PIC 9(16).
           05  CUST-CONSENT-FLAG   PIC X(01).

       LINKAGE SECTION.
       01  LS-RETURN-CODE          PIC 9(04).

       PROCEDURE DIVISION USING LS-RETURN-CODE.

       0000-MAIN.
           PERFORM 1000-READ-CUSTOMER
           PERFORM 2000-DISPLAY-DETAILS
           PERFORM 3000-LOG-AUDIT
           PERFORM 4000-CALL-PROGB
           STOP RUN.

       1000-READ-CUSTOMER.
           MOVE 1234567890         TO CUST-ID
           READ CUSTFILE INTO CUSTOMER-RECORD
               AT END
                   MOVE 8 TO WS-RETURN-CODE
               NOT AT END
                   CONTINUE
           END-READ.

       2000-DISPLAY-DETAILS.
           MOVE CUST-FIRST-NAME    TO WS-DISPLAY-LINE
           DISPLAY WS-DISPLAY-LINE
           DISPLAY CUST-SSN
           DISPLAY CUST-DOB.

       3000-LOG-AUDIT.
           MOVE CUST-SSN           TO WS-AUDIT-SSN
           MOVE CUST-FIRST-NAME    TO WS-AUDIT-NAME
           MOVE 'VIEW'             TO WS-AUDIT-ACTION
           WRITE CUSTFILE-REC FROM WS-AUDIT-REC.

       4000-CALL-PROGB.
           CALL 'PROGB' USING CUSTOMER-RECORD
                              WS-RETURN-CODE.
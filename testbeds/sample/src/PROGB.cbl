IDENTIFICATION DIVISION.
       PROGRAM-ID. PROGB.

       ENVIRONMENT DIVISION.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT ARCHIVEFILE ASSIGN TO 'CUSTARCH'
               ORGANIZATION IS SEQUENTIAL.
           SELECT EXPORTFILE ASSIGN TO 'EXTEXPORT'
               ORGANIZATION IS SEQUENTIAL.

       DATA DIVISION.
       FILE SECTION.
       FD  ARCHIVEFILE.
       01  ARCHIVE-REC.
           05  AR-CUST-ID          PIC 9(10).
           05  AR-CUST-SSN         PIC 9(09).
           05  AR-CUST-NAME        PIC X(25).

       FD  EXPORTFILE.
       01  EXPORT-REC.
           05  EX-CUST-ID          PIC 9(10).
           05  EX-CUST-CARD        PIC 9(16).
           05  EX-CUST-EMAIL       PIC X(50).

       WORKING-STORAGE SECTION.
       01  WS-PROGB-RC             PIC 9(04) VALUE ZEROS.

       LINKAGE SECTION.
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
       01  LS-RETURN-CODE          PIC 9(04).

       PROCEDURE DIVISION USING CUSTOMER-RECORD
                                  LS-RETURN-CODE.

       0000-MAIN.
           OPEN OUTPUT ARCHIVEFILE
           OPEN OUTPUT EXPORTFILE
           PERFORM 1000-ARCHIVE-CUSTOMER
           PERFORM 2000-EXPORT-CUSTOMER
           CLOSE ARCHIVEFILE
           CLOSE EXPORTFILE
           MOVE WS-PROGB-RC TO LS-RETURN-CODE
           GOBACK.

       1000-ARCHIVE-CUSTOMER.
           MOVE CUST-ID            TO AR-CUST-ID
           MOVE CUST-SSN           TO AR-CUST-SSN
           MOVE CUST-FIRST-NAME    TO AR-CUST-NAME
           WRITE ARCHIVE-REC.

       2000-EXPORT-CUSTOMER.
           MOVE CUST-ID            TO EX-CUST-ID
           MOVE CUST-CARD-NUM      TO EX-CUST-CARD
           MOVE CUST-EMAIL         TO EX-CUST-EMAIL
           WRITE EXPORT-REC.
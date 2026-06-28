*----------------------------------------------------------------*
      * CVCUS01Y.cpy                                                   *
      * Customer record copybook                                        *
      *----------------------------------------------------------------*
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
               88  CONSENT-GIVEN   VALUE 'Y'.
               88  CONSENT-DENIED  VALUE 'N'.
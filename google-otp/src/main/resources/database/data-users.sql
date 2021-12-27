INSERT INTO USERS (USER_ID, PASSWORD, OTP_SCT_KEY, USER_NM, EMAIL, CRT_ID, CRT_DT, MDF_ID, MDF_DT)
VALUES ('user-1', '$2a$10$KrjenrXd92k2XaAfVjyWBukKwJMvYsztjNQwEdDkdQUgpy4zMY2LS', '5OCVN5CARM6SXY3QGC2BPPJH7I5QZ73V',
        'George Washington', 'george@gmail.com', 'system', NOW(), 'system', NOW()),
       ('user-2', '$2a$10$0gLBV1Mri5kZS5NLaauiTeJXM6DmRnrV4CPyOQ57UmwOOdWdTZnbm', 'SEE7RM2KBF5PDUKCP7GOA7TCK5XSP2BJ',
        'William de Hertburn', 'william@gmail.com', 'system', NOW(), 'system', NOW());


DROP DATABASE IF EXISTS project2;
CREATE DATABASE project2;
USE project2;

-- Table for institute master
CREATE TABLE institution_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    institution_id VARCHAR(50) UNIQUE,
    institution_name VARCHAR(250),
    location varchar(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active'
);

DELIMITER //
CREATE TRIGGER before_insert_institution_master
BEFORE INSERT ON institution_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'institution_master');
    SET NEW.institution_id = CONCAT('INS', next_id);
END//
DELIMITER ;

-- Table for department master
CREATE TABLE department_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dept_id VARCHAR(50) UNIQUE,
    user_name VARCHAR(50),
    department_name VARCHAR(40),
    institution_id VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active',
    FOREIGN KEY (institution_id) REFERENCES institution_master(institution_id)
);

DELIMITER //
CREATE TRIGGER before_insert_department_master
BEFORE INSERT ON department_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'department_master');
    SET NEW.dept_id = CONCAT('DEPT', next_id);
END//
DELIMITER ;

-- Table for user type master
CREATE TABLE user_type_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_type_id VARCHAR(50) UNIQUE,
    password VARCHAR(255),
    user_type_type ENUM('admin', 'superAdmin', 'employee', 'committee') DEFAULT 'employee',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active'
);

DELIMITER //
CREATE TRIGGER before_insert_user_type_master
BEFORE INSERT ON user_type_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_type_master');
    SET NEW.user_type_id = CONCAT('USERTY', next_id);
END//
DELIMITER ;

-- Table for user master
-- Step 1: Create the `user_master` table
CREATE TABLE user_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(50) UNIQUE,
    first_name VARCHAR(20),
    middle_name VARCHAR(20),
    last_name VARCHAR(20),
    email_id VARCHAR(40) UNIQUE,
    contact_no VARCHAR(10),
    pan_card_no VARCHAR(10) UNIQUE,
    addhar_no VARCHAR(12) UNIQUE,
    emp_id VARCHAR(50),
    institution_id VARCHAR(50),
    dept_id VARCHAR(50),
    user_type_id VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active',
    FOREIGN KEY (institution_id) REFERENCES institution_master(institution_id),
    FOREIGN KEY (dept_id) REFERENCES department_master(dept_id),
    FOREIGN KEY (user_type_id) REFERENCES user_type_master(user_type_id)
);





DELIMITER //
CREATE TRIGGER before_insert_user_master
BEFORE INSERT ON user_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_master');
    SET NEW.user_id = CONCAT('USR', next_id);
END//
DELIMITER ;


-- Table for criteria master
CREATE TABLE criteria_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    criteria_id VARCHAR(50) UNIQUE,
    criteria_description VARCHAR(240),
    max_marks INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active',
    type ENUM('self', 'appraisal') DEFAULT 'self'

);

DELIMITER //
CREATE TRIGGER before_insert_criteria_master
BEFORE INSERT ON criteria_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'criteria_master');
    SET NEW.criteria_id = CONCAT('CRIT', next_id);
END//
DELIMITER ;

-- Table for criteria parameter master
CREATE TABLE c_parameter_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    c_parameter_id VARCHAR(50) UNIQUE,
    parameter_description_type enum ('required' ,'optional') default 'required',
    parameter_description varchar(250),
    parameter_max_marks INT,
    criteria_id VARCHAR(50) ,
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active', type ENUM('self', 'appraisal') DEFAULT 'self',
    FOREIGN KEY (criteria_id) REFERENCES criteria_master(criteria_id)
);


DELIMITER //
CREATE TRIGGER before_insert_c_parameter_master
BEFORE INSERT ON c_parameter_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'c_parameter_master');
    SET NEW.c_parameter_id = CONCAT('C_PARA', next_id);
END//
DELIMITER ;


-- Table for  appraisal master


CREATE TABLE apprisal_master 
(
  id INT AUTO_INCREMENT PRIMARY KEY,
  apprisal_id VARCHAR2(10) unique,
  apprisal_cycle_name varchar(250),
  start_date date,
  end_date date,
  institution_id VARCHAR(50),
  dept_id varchar(50),
   criteria_id VARCHAR(50) ,
    FOREIGN KEY (criteria_id) REFERENCES criteria_master(criteria_id)
    FOREIGN KEY (institution_id) REFERENCES institution_master(institution_id),
    FOREIGN KEY (dept_id) REFERENCES department_master(dept_id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active',
    
);

DELIMITER //
CREATE TRIGGER before_insert_appraisal_master 
BEFORE INSERT ON appraisal_master 
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES 
                   WHERE TABLE_SCHEMA = DATABASE() 
                   AND TABLE_NAME = 'appraisal_master');
    SET NEW.appraisal_id = CONCAT('APPR', next_id);
END//
DELIMITER ;



-- Table for  appraisalcriteriraparamaster score master


CREATE TABLE apprisal_criteria_parameter_master 
(
  id INT AUTO_INCREMENT PRIMARY KEY,
  ACP_id VARCHAR(10) unique,
  criteria_id VARCHAR(50),
  FOREIGN KEY (criteria_id) REFERENCES criteria_master(criteria_id),
  c_parameter_id VARCHAR(50),
  appraisal_id varchar(10),
  total_marks int ,
  FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id),
  FOREIGN KEY (c_parameter_id) REFERENCES c_parameter_master(c_parameter_id),
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  status ENUM('active', 'inactive') DEFAULT 'active'
);



DELIMITER //
CREATE TRIGGER apprisal_criteria_parameter_master 
BEFORE INSERT ON apprisal_criteria_parameter_master 
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'apprisal_criteria_parameter_master ');
    SET NEW.ACP_id = CONCAT('ACP', next_id);
END//
DELIMITER ;




-- Table for self appraisal score master
CREATE TABLE self_appraisal_score_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    record_id VARCHAR(50) UNIQUE,
    user_id VARCHAR(50), 
    marks_by_emp INT,
    c_parameter_id VARCHAR(50),
    appraisal_id VARCHAR(50),
    
    -- Adding timestamps and status
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active',
    
    -- Foreign Key constraints
    FOREIGN KEY (user_id) REFERENCES user_master(user_id),
    FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id),
    FOREIGN KEY (c_parameter_id) REFERENCES c_parameter_master(c_parameter_id)
);

DELIMITER //
CREATE TRIGGER before_insert_self_appraisal_score_master
BEFORE INSERT ON self_appraisal_score_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'self_appraisal_score_master');
    SET NEW.record_id = CONCAT('SASM', next_id);
END//
DELIMITER ;


-- Table for committee master
CREATE TABLE committee_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    committee_record_id VARCHAR(50) UNIQUE,
    record_id VARCHAR(50) , FOREIGN key (record_id) REFERENCES self_appraisal_score_master(record_id),
    user_id_employee VARCHAR(50),
    user_id_committee VARCHAR(50),
    comm_score INT,
    c_parameter_id VARCHAR(50), FOREIGN KEY (c_parameter_id) REFERENCES c_parameter_master(c_parameter_id),
    appraisal_id varchar(50) , FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active',
    FOREIGN KEY (user_id_employee) REFERENCES user_master(user_id),
    FOREIGN KEY (user_id_committee) REFERENCES user_master(user_id)
   
);

DELIMITER //
CREATE TRIGGER before_insert_committee_master
BEFORE INSERT ON committee_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'committee_master');
    SET NEW.committee_record_id = CONCAT('COM', next_id);

END//
DELIMITER ;


CREATE TABLE document_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    document_id VARCHAR(50) UNIQUE,
    user_id VARCHAR(250),FOREIGN KEY (user_id) REFERENCES user_master(user_id),
      c_parameter_id VARCHAR(50), FOREIGN KEY (c_parameter_id) REFERENCES c_parameter_master(c_parameter_id),
      doc_count int DEFAULT 0,
      doc_link varchar(250),
    location varchar(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active'
);
  
DELIMITER //
CREATE TRIGGER before_document_master
BEFORE INSERT ON document_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'document_master');
    SET NEW.document_id = CONCAT('DOC', next_id);
END//
DELIMITER ;

create table review_master(
    id INT AUTO_INCREMENT PRIMARY KEY,
    review_id VARCHAR(50) UNIQUE,
    user_id VARCHAR(250),FOREIGN KEY (user_id) REFERENCES user_master(user_id),
    criteria_id VARCHAR(50),
    FOREIGN KEY (criteria_id) REFERENCES criteria_master(criteria_id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active'
);

DELIMITER //
CREATE TRIGGER before_review_master
BEFORE INSERT ON review_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'review_master');
    SET NEW.review_id = CONCAT('REI', next_id);
END//
DELIMITER ;



CREATE TABLE grade_master 
(
  id INT AUTO_INCREMENT PRIMARY KEY,
  grade_id VARCHAR(10) UNIQUE,
  appraisal_id VARCHAR(50),
  grade_title VARCHAR(250),
  min_marks VARCHAR(50),
  max_marks VARCHAR(50),
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  status ENUM('active', 'inactive') DEFAULT 'active',
  FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id) 
);
DELIMITER //

CREATE TRIGGER before_grade_master_insert
BEFORE INSERT ON grade_master 
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    
    -- Get the next auto-increment value for the appraisal_master table
    SET next_id = (SELECT AUTO_INCREMENT 
                   FROM information_schema.TABLES 
                   WHERE TABLE_SCHEMA = DATABASE() 
                   AND TABLE_NAME = 'grade_master ');
    
    -- Set the new appraisal_id to be 'APP' followed by the next_id
    SET NEW.grade_id = CONCAT('grade', next_id);
END//

DELIMITER ;


create table appraisal_master(
    id INT AUTO_INCREMENT PRIMARY KEY,
    appraisal_id VARCHAR(50) UNIQUE,
    appraisal_cycle_name varchar(250),
    user_id VARCHAR(250),FOREIGN KEY (user_id) REFERENCES user_master(user_id),
    start_date DATE,
    end_date DATE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active'
);












DELIMITER //

CREATE TRIGGER before_appraisal_master_insert
BEFORE INSERT ON appraisal_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    
    -- Get the next auto-increment value for the appraisal_master table
    SET next_id = (SELECT AUTO_INCREMENT 
                   FROM information_schema.TABLES 
                   WHERE TABLE_SCHEMA = DATABASE() 
                   AND TABLE_NAME = 'appraisal_master');
    
    -- Set the new appraisal_id to be 'APP' followed by the next_id
    SET NEW.appraisal_id = CONCAT('APP', next_id);
END//

DELIMITER ;



INSERT INTO appraisal_master (appraisal_cycle_name, user_id, status)
VALUES 
('2024 Mid-Year Review', 'USR17', 'active'),
('2024 End-of-Year Review', 'USR17', 'active');



create table appraisal_departments(
    id INT AUTO_INCREMENT PRIMARY KEY,
    appraisal_dept_id VARCHAR(50) UNIQUE,
    appraisal_id VARCHAR(50),
    FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id),
    department_id VARCHAR(50),
    FOREIGN KEY (department_id) REFERENCES department_master(dept_id),
    institution_id VARCHAR(50),
    FOREIGN KEY (institution_id) REFERENCES institution_master(institution_id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active'
    
);

DELIMITER //
CREATE TRIGGER before_appraisal_departments_insert
BEFORE INSERT ON appraisal_departments
FOR EACH ROW
BEGIN
    DECLARE next_id INT;

    -- Get the next auto-increment value for the appraisal_departments table
    SELECT IFNULL(MAX(CAST(SUBSTRING(appraisal_dept_id, 3) AS UNSIGNED)), 0) + 1 INTO next_id
    FROM appraisal_departments;

    -- Set the new appraisal_dept_id to be 'AD' followed by the next_id
    SET NEW.appraisal_dept_id = CONCAT('AD', next_id);
END//
DELIMITER ;

    


INSERT INTO appraisal_departments (appraisal_id, department_id, institution_id, status)
VALUES 
('APP3', 'DEPT10', 'INS8', 'active'),

('APP5', 'DEPT10', 'INS8', 'active');



insert into criteria_master (criteria_description, max_marks) values ('Teaching, Learning and Evaluation',260);
insert into criteria_master (criteria_description, max_marks) values ('Research Publications',210);
insert into criteria_master (criteria_description, max_marks) values ('Continuous Professional Education',110);
insert into criteria_master (criteria_description, max_marks) values ('Representation as a Resource Person',150);
insert into criteria_master (criteria_description, max_marks) values ('Contributions in Institutional Activities and Support to and Progression of Students', 150);
insert into criteria_master (criteria_description, max_marks) values ('Administrative Responsibilities',120);

Alter table user_type_master add  user_name varchar(255);

insert into institution_master (institution_name,location) values ("Fergusson College","Pune");
insert into department_master (department_name,institution_id) values ("CS","INS1");
insert into user_type_master (user_name,password) values ("test","test");
insert into user_type_master (user_name,password , user_type_type) values ("Nancy","pass","admin");
insert into user_master(institution_id,dept_id,user_type_id) values ("INS1","DEPT1","USERTY2");
 SELECT COUNT(*) AS count FROM user_master WHERE status = "pending" AND institution_id = "INS1";




  SELECT 
                c.criteria_id AS 'Criteria Number',
                c.criteria_description AS 'Criteria Name',
                CASE 
                    WHEN sas.record_id IS NULL THEN 'Pending'
                    WHEN cm.id IS NOT NULL THEN 'Approved'
                    ELSE 'Applied'
                END AS 'Status',
                CASE 
                    WHEN sas.record_id IS NULL THEN 'Apply'
                    WHEN cm.id IS NOT NULL THEN 'View'
                    ELSE 'Edit'
                END AS 'Action'
            FROM 
                criteria_master c
            LEFT JOIN 
                self_appraisal_score_master sas ON c.criteria_id = sas.c_parameter_id AND sas.user_id = "USR5"
            LEFT JOIN 
                committee_master cm ON c.criteria_id = cm.c_parameter_id AND cm.user_id_employee ="USR5"
            WHERE 
                c.status = 'active';






                 SELECT c.criteria_description AS 'Criteria Name', cp.*
            FROM criteria_master c
            JOIN c_parameter_master cp ON c.criteria_id = cp.criteria_id
            WHERE c.criteria_id = "CRIT1" AND cp.status = 'active';











--Criteria Status


  SELECT c.criteria_id AS 'Criteria Number',
                c.criteria_description AS 'Criteria Name',
                CASE
                    WHEN MAX(sas.record_id) IS NOT NULL THEN 'Applied'
                    ELSE 'Not Applied'
                END AS 'Self-Appraisal Status',
                CASE
                    WHEN MAX(cm.record_id) IS NOT NULL THEN 'Reviewed'
                    ELSE 'Not Reviewed'
                END AS 'Committee Status'
            FROM criteria_master c
            LEFT JOIN c_parameter_master p
                ON c.criteria_id = p.criteria_id
            LEFT JOIN self_appraisal_score_master sas
                ON p.c_parameter_id = sas.c_parameter_id AND sas.user_id ="USR9" AND sas.status = 'active'
            LEFT JOIN committee_master cm
                ON p.c_parameter_id = cm.c_parameter_id AND cm.user_id_employee ="USR9" AND cm.status = 'active'
            WHERE c.status = 'active'
            GROUP BY c.criteria_id, c.criteria_description;



--criteria View

               SELECT c.criteria_id AS 'Criteria Number',
                c.criteria_description AS 'Criteria Name',
                COALESCE(sas.max_marks, 'Not Available') AS 'Max Marks',
                COALESCE(sas.self_approved_marks, 'Not Available') AS 'Self-Approved Marks',
                COALESCE(cm.marks_by_committee, 'Not Available') AS 'Marks by Committee',
                d.document_url AS 'Document URL'
            FROM criteria_master c
            LEFT JOIN self_appraisal_score_master sas
                ON c.criteria_id = sas.criteria_id AND sas.user_id ="USR5" AND sas.status = 'active'
            LEFT JOIN committee_master cm
                ON c.criteria_id = cm.criteria_id AND cm.user_id_employee ="USR5" AND cm.status = 'active'
            LEFT JOIN document_master d
                ON c.criteria_id = d.criteria_id
            WHERE c.criteria_id = "CRIT1";








insert into user_type_master (user_name,password,user_type_type) values("apurva","password","committee");            
insert into user_master(institution_id,dept_id,user_type_id) values ("INS1","DEPT1","USERTY8");

insert into user_type_master (user_name,password,user_type_type) values("prernajaju1703@gmail.com","password","admin"); 

insert into user_type_master (user_name,password,user_type_type) values("patumane3638@gmail.com","password","committee"); 
insert into user_master(institution_id,dept_id,user_type_id) values ("INS2","DEPT2","USERTY7");

-- Insert values into user_master
INSERT INTO user_master (first_name, middle_name, last_name, email_id, contact_no, pan_card_no, addhar_no,  institution_id,dept_id, user_type_id)
VALUES
( 'Prerna ', 'Shrinivas', 'Jaju', 'prernajaju1703@gmail.com', '1234567890', 'ABCDE1234F', '123456789012', 'INS1',"DEPT1","USERTY15");

CREATE TABLE OTP_MASTER (ID INT AUTO_INCREMENT PRIMARY KEY, OTP_ID VARCHAR(250) UNIQUE, EMAIL_ID VARCHAR(250), FOREIGN KEY(EMAIL_ID) REFERENCES USER_type_MASTER(user_name), OTP VARCHAR(10), TIMESTAMP TIMESTAMP DEFAULT CURRENT_TIMESTAMP, STATUS ENUM('active', 'inactive') DEFAULT "active");
DELIMITER // CREATE TRIGGER BEFORE_INSERT_OTP_MASTER BEFORE INSERT ON OTP_MASTER FOR EACH ROW BEGIN DECLARE NEXT_ID INT;
SET NEXT_ID = (
  SELECT
    AUTO_INCREMENT
  FROM
    INFORMATION_SCHEMA.TABLES
  WHERE
    TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'otp_master'
);
SET NEW.OTP_ID = CONCAT('OTP', NEXT_ID);
END// DELIMITER;

insert into user_type_master (user_name,password,user_type_type) values("superAdmin","superAdmin" , 'superAdmin');

Alter table user_type_master auto_increment = 0;
Alter table institution_master auto_increment = 0;
Alter table department_master auto_increment = 0;
Alter table otp_master auto_increment = 0;
Alter table criteria_master auto_increment = 0;
Alter table user_master auto_increment = 0;
Alter table committee_master auto_increment = 0;
Alter table self_appraisal_score_master auto_increment = 0;
Alter table c_parameter_master auto_increment = 0;
Alter table document_master auto_increment = 0;   
insert into institution_master (institution_name,location) values ("Fergusson College","Pune");
insert into department_master (department_name,institution_id) values ("CS","INS1");
insert into user_type_master (user_name,password,user_type_type) values ("apurva3barthwal@gmail.com","password","admin");
insert into user_master(institution_id,dept_id,user_type_id) values ("INS1","DEPT1","USERTY1");
ALTER TABLE self_appraisal_score_master
ADD COLUMN supportive_document ENUM('proof', 'no proof') DEFAULT 'proof';
Alter table appraisal_master = 0;
Alter table appraisal_departments auto_increment = 0;
Alter table appraisal_members auto_increment = 0;

-- Step 1: Create the `committee_master` table
CREATE TABLE committee_member_master (
    id int AUTO_INCREMENT PRIMARY KEY,
    committee_id VARCHAR(50) UNIQUE,
    user_id VARCHAR(50),
    institution_id VARCHAR(50),
    start_date DATE,
    end_date DATE,
        appraisal_id varchar(50) , FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id),

    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES user_master(user_id),
    FOREIGN KEY (institution_id) REFERENCES institution_master(institution_id)
);



CREATE TABLE payment_orders (
    order_id VARCHAR(255) PRIMARY KEY,  -- Razorpay Order ID
    principal_email VARCHAR(255) NOT NULL,  -- Email of the principal
    institution_id VARCHAR(255) NOT NULL,  -- Foreign key to institution_master
    payment_status ENUM('created', 'paid', 'failed') DEFAULT 'created',  -- Payment status
    amount INT NOT NULL,  -- Amount paid (in paise, e.g. 20000 INR = 2000000 paise)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Timestamp when order was created
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,  -- Timestamp for updates
    FOREIGN KEY (institution_id) REFERENCES institution_master(institution_id) ON DELETE CASCADE,
    FOREIGN KEY (principal_email) REFERENCES user_type_master(user_name)
);

insert into department_master (department_name,institution_id) values ("Maths","INS8");
insert into department_master (department_name,institution_id) values ("Physics","INS8");
insert into department_master (department_name,institution_id) values ("Computer Applications","INS8");
insert into department_master (department_name,institution_id) values ("Biology","INS8");



-- for committee
-- Step 1: Add the column
ALTER TABLE committee_master 
ADD appraisal_id VARCHAR(50);
-- Step 1: Add the column
ALTER TABLE committee_master 
ADD appraisal_id VARCHAR(50);

-- Step 2: Add the foreign key constraint
ALTER TABLE committee_master 
ADD CONSTRAINT fk_appraisal_id 
FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id);

-- Step 2: Add the foreign key constraint
ALTER TABLE committee_master 
ADD CONSTRAINT fk_appraisal_id 
FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id);

-- for self appraisal master 

ALTER TABLE self_appraisal_score_master 
ADD appraisal_id VARCHAR(50);

ALTER TABLE self_appraisal_score_master 
ADD CONSTRAINT fk_appraisal_id 
FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id);

-- for documnet master

ALTER TABLE document_master
ADD appraisal_id VARCHAR(50);

ALTER TABLE document_master
ADD CONSTRAINT fk_appraisal_id 
FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id);


CREATE TABLE appraisal_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    appmember_id VARCHAR(50) UNIQUE , 
    appraisal_id VARCHAR(50), 
    committee_id VARCHAR(50), 
    user_id VARCHAR(50), 
    FOREIGN KEY (appraisal_id) REFERENCES appraisal_master(appraisal_id) ON DELETE CASCADE,
    FOREIGN KEY (committee_id) REFERENCES committee_member_master(committee_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES user_master(user_id) ON DELETE CASCADE,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);



DELIMITER //
CREATE TRIGGER before_insert_appraisal_members
BEFORE INSERT ON appraisal_members
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
  
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES 
                   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'appraisal_members');
   
    SET NEW.appmember_id = CONCAT('APPMember', next_id);
END//
DELIMITER ;

-- Step 2: Create a trigger for generating unique committee_id
DELIMITER //
CREATE TRIGGER before_insert_committee_member_master
BEFORE INSERT ON committee_member_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
 SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES 
                   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'committee_member_master');  
    SET NEW.committee_id = CONCAT('COMMIT', next_id);
END//
DELIMITER ;

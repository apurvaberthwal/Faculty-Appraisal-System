
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
    status ENUM('active', 'inactive') DEFAULT 'active'
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
    criteria_id VARCHAR(50),
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active',
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

-- Table for self appraisal score master
CREATE TABLE self_appraisal_score_master (
    id INT AUTO_INCREMENT PRIMARY KEY,
    record_id VARCHAR(50) UNIQUE,
    user_id VARCHAR(50), FOREIGN KEY (user_id) REFERENCES user_master(user_id),
    marks_by_emp INT,   
    c_parameter_id VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'inactive') DEFAULT 'active',
   
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

-- Step 1: Create the `committee_master` table
CREATE TABLE committee_member_master (
    id int AUTO_INCREMENT PRIMARY KEY,
    committee_id VARCHAR(50) UNIQUE,
    user_id VARCHAR(50),
    institution_id VARCHAR(50),
    start_date DATE,
    end_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_master(user_id),
    FOREIGN KEY (institution_id) REFERENCES institution_master(institution_id)
);

-- Step 2: Create a trigger for generating unique committee_id
DELIMITER //
CREATE TRIGGER before_insert_committee_member_master
BEFORE INSERT ON committee_member_master
FOR EACH ROW
BEGIN
    DECLARE next_id INT;
    SET next_id = (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'committee_member_master');
    SET NEW.committee_id = CONCAT('COMMIT', next_id);
END//
DELIMITER ;

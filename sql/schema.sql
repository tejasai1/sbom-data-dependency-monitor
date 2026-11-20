
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `app_settings` (
  `setting_key` varchar(100) NOT NULL,
  `setting_value` varchar(500) DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `data_dependency` (
  `dependency_id` int NOT NULL AUTO_INCREMENT,
  `source_target_pk` int NOT NULL,
  `source_package_id` int DEFAULT NULL,
  `dest_target_pk` int NOT NULL,
  `dest_package_id` int DEFAULT NULL,
  `data_type` varchar(100) DEFAULT NULL,
  `description` varchar(500) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`dependency_id`),
  KEY `idx_dep_source` (`source_target_pk`),
  KEY `idx_dep_dest` (`dest_target_pk`),
  KEY `fk_dep_source_package` (`source_package_id`),
  KEY `fk_dep_dest_package` (`dest_package_id`),
  CONSTRAINT `fk_dep_dest_package` FOREIGN KEY (`dest_package_id`) REFERENCES `packages_name` (`package_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_dep_dest_target` FOREIGN KEY (`dest_target_pk`) REFERENCES `monitored_targets` (`target_pk`) ON DELETE CASCADE,
  CONSTRAINT `fk_dep_source_package` FOREIGN KEY (`source_package_id`) REFERENCES `packages_name` (`package_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_dep_source_target` FOREIGN KEY (`source_target_pk`) REFERENCES `monitored_targets` (`target_pk`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=41 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `impact_report` (
  `report_id` int NOT NULL AUTO_INCREMENT,
  `target_pk` int NOT NULL,
  `facts_hash` char(64) NOT NULL,
  `model` varchar(100) NOT NULL,
  `report_json` mediumtext NOT NULL,
  `problems_json` text NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`report_id`),
  KEY `idx_impact_lookup` (`target_pk`,`facts_hash`,`model`),
  CONSTRAINT `fk_impact_target` FOREIGN KEY (`target_pk`) REFERENCES `monitored_targets` (`target_pk`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `monitor_log` (
  `log_id` int NOT NULL AUTO_INCREMENT,
  `target_id` varchar(500) NOT NULL,
  `latest_scan_id` int NOT NULL,
  `prev_scan_id` int DEFAULT NULL,
  `scan_time` datetime NOT NULL,
  `total_vulns` int DEFAULT '0',
  `critical` int DEFAULT '0',
  `high` int DEFAULT '0',
  `medium` int DEFAULT '0',
  `low` int DEFAULT '0',
  `new_found` int DEFAULT '0',
  `resolved` int DEFAULT '0',
  `scan_id_latest` int DEFAULT NULL,
  `scan_id_prev` int DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`log_id`),
  UNIQUE KEY `uq_target_latest_scan` (`target_id`,`latest_scan_id`)
) ENGINE=InnoDB AUTO_INCREMENT=582 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `monitored_targets` (
  `target_pk` int NOT NULL AUTO_INCREMENT,
  `target_id` varchar(500) NOT NULL,
  `target_type` varchar(50) DEFAULT 'github',
  `source_name` varchar(100) DEFAULT 'dr_charles',
  `active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `last_scan_time` datetime DEFAULT NULL,
  `notes` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`target_pk`),
  UNIQUE KEY `target_id` (`target_id`)
) ENGINE=InnoDB AUTO_INCREMENT=32 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `package_vuln_observation` (
  `spr_id` int NOT NULL AUTO_INCREMENT,
  `scan_id` int NOT NULL,
  `package_id` int NOT NULL,
  `vulnerability_id` int NOT NULL,
  `detected_version` varchar(1000) DEFAULT NULL,
  `fixed_version` varchar(1000) DEFAULT NULL,
  `observed_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`spr_id`),
  KEY `scan_id` (`scan_id`),
  KEY `package_id` (`package_id`),
  KEY `vulnerability_id` (`vulnerability_id`),
  CONSTRAINT `package_vuln_observation_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scan` (`scan_id`) ON DELETE CASCADE,
  CONSTRAINT `package_vuln_observation_ibfk_2` FOREIGN KEY (`package_id`) REFERENCES `packages_name` (`package_id`) ON DELETE CASCADE,
  CONSTRAINT `package_vuln_observation_ibfk_3` FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerability` (`vulnerability_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=85945 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `packages_name` (
  `package_id` int NOT NULL AUTO_INCREMENT,
  `package_name` varchar(255) NOT NULL,
  `version` varchar(100) NOT NULL,
  PRIMARY KEY (`package_id`),
  UNIQUE KEY `uq_package_version` (`package_name`,`version`)
) ENGINE=InnoDB AUTO_INCREMENT=333856 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scan` (
  `scan_id` int NOT NULL AUTO_INCREMENT,
  `target_id` varchar(500) NOT NULL,
  `scan_time` datetime NOT NULL,
  PRIMARY KEY (`scan_id`),
  KEY `idx_scan_target_scan` (`target_id`,`scan_id`)
) ENGINE=InnoDB AUTO_INCREMENT=583 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `suggested_dependency` (
  `suggestion_id` int NOT NULL AUTO_INCREMENT,
  `source_target_pk` int NOT NULL,
  `dest_target_pk` int NOT NULL,
  `found_in_target_pk` int NOT NULL,
  `data` varchar(500) NOT NULL,
  `items_json` text NOT NULL,
  `category` varchar(30) NOT NULL,
  `mechanism` varchar(30) NOT NULL,
  `confidence` varchar(10) NOT NULL,
  `reason` varchar(200) NOT NULL,
  `evidence_json` mediumtext NOT NULL,
  `model` varchar(100) NOT NULL,
  `status` varchar(10) NOT NULL DEFAULT 'pending',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `decided_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`suggestion_id`),
  KEY `idx_sugg_pair` (`source_target_pk`,`dest_target_pk`),
  KEY `idx_sugg_status` (`status`),
  KEY `fk_sugg_dest` (`dest_target_pk`),
  KEY `fk_sugg_found` (`found_in_target_pk`),
  CONSTRAINT `fk_sugg_dest` FOREIGN KEY (`dest_target_pk`) REFERENCES `monitored_targets` (`target_pk`) ON DELETE CASCADE,
  CONSTRAINT `fk_sugg_found` FOREIGN KEY (`found_in_target_pk`) REFERENCES `monitored_targets` (`target_pk`) ON DELETE CASCADE,
  CONSTRAINT `fk_sugg_source` FOREIGN KEY (`source_target_pk`) REFERENCES `monitored_targets` (`target_pk`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulnerability` (
  `vulnerability_id` int NOT NULL AUTO_INCREMENT,
  `cve_id` varchar(100) NOT NULL,
  `severity` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`vulnerability_id`),
  UNIQUE KEY `uq_cve` (`cve_id`)
) ENGINE=InnoDB AUTO_INCREMENT=85945 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;


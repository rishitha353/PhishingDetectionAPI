package com.phishingdetection.repository;

import com.phishingdetection.model.UrlCheck;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UrlCheckRepository extends JpaRepository<UrlCheck, Long> {
}
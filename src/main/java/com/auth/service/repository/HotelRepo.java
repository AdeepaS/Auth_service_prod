package com.auth.service.repository;

import com.auth.service.entity.HotelEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface HotelRepo extends JpaRepository<HotelEntity, UUID> {
}

package com.tuandanh.profileService.repository;

import com.tuandanh.profileService.entity.Friendship;
import com.tuandanh.profileService.enums.FriendStatus;
import org.springframework.data.repository.query.Param;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.data.neo4j.repository.query.Query;

import java.util.List;
import java.util.Optional;

public interface FriendshipRepository extends Neo4jRepository<Friendship, String> {
    @Query("MATCH (f:FriendshipRequest) WHERE f.senderId = $senderId AND f.receiverId = $receiverId RETURN f")
    Optional<Friendship> findBySenderIdAndReceiverId(String senderId, String receiverId);

    @Query("MATCH (f:FriendshipRequest) WHERE f.receiverId = $receiverId AND f.status = $friendStatus RETURN f")
    List<Friendship> findAllByReceiverIdAndStatus(String receiverId, FriendStatus friendStatus);

    @Query("MATCH (a:User_Profile)-[f:FRIENDSHIP]-(b:User_Profile) " +
            "WHERE a.id = $profileId AND b.id = $targetProfileId " +
            "RETURN f.status")
    Optional<FriendStatus> findFriendshipStatus(@Param("profileId") String profileId,
                                                    @Param("targetProfileId") String targetProfileId);

}

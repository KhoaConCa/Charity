package com.tuandanh.profileService.repository;

import com.tuandanh.profileService.entity.UserProfile;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.data.neo4j.repository.query.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserProfileRepository extends Neo4jRepository<UserProfile, String> {
    List<UserProfile> findByUserId(String userId);

    @Query("MATCH (a:User_Profile)-[:BLOCKS]->(b:User_Profile) WHERE a.profileId = $profileId RETURN b")
    List<UserProfile> findBlockedProfiles(String profileId);

    @Query("MATCH (a:User_Profile {profileId: $blockerId})-[r:BLOCKS]->(b:User_Profile {profileId: $blockingId})" +
            " RETURN COUNT(r)")
    long isBlocking(String blockerId, String blockingId);

    @Query("MATCH (a:User_Profile {profileId: $blockerId}), (b:User_Profile {profileId: $blockingId}) " +
            "MERGE (a)-[:BLOCKS]->(b)")
    void blockProfile(String blockerId, String blockingId);

    @Query("MATCH (a:User_Profile {profileId: $blockerId})-[r:BLOCKS]->(b:User_Profile {profileId: $blockingId}) " +
            "DELETE r")
    void unblockProfile(String blockerId, String blockingId);

    @Query("MATCH (a:User_Profile {profileId: $followerId})-[r:FOLLOWS]->(b:User_Profile {profileId: $followingId})" +
            " RETURN COUNT(r)")
    long isFollowing(String followerId, String followingId);

    @Query("MATCH (a:User_Profile)-[:FOLLOWS]->(b:User_Profile) WHERE a.profileId = $profileId RETURN b")
    List<UserProfile> findFollowingProfiles(String profileId);

    @Query("MATCH (a:User_Profile)<-[:FOLLOWS]-(b:User_Profile) WHERE a.profileId = $profileId RETURN b")
    List<UserProfile> findFollowers(String profileId);

    @Query("MATCH (a:User_Profile {profileId: $followerId}), (b:User_Profile {profileId: $followingId}) " +
            "MERGE (a)-[:FOLLOWS]->(b)")
    void followProfile(String followerId, String followingId);

    @Query("MATCH (a:User_Profile {profileId: $followerId})-[r:FOLLOWS]->(b:User_Profile {profileId: $followingId}) " +
            "DELETE r")
    void unfollowProfile(String followerId, String followingId);

    @Query("MATCH (a:User_Profile {profileId: $followerId}), (b:User_Profile {profileId: $followingId}) " +
            "MERGE (a)-[:FRIENDSHIP]-(b)")
    void addFriend(String followerId, String followingId);

    @Query("MATCH (a:User_Profile {profileId: $followerId})-[r:FRIENDSHIP]-(b:User_Profile {profileId: $followingId}) " +
            "DELETE r")
    void removeFriend(String followerId, String followingId);

}

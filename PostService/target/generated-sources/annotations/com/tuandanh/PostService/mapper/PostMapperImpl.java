package com.tuandanh.PostService.mapper;

import com.tuandanh.PostService.dto.response.PostResponse;
import com.tuandanh.PostService.entity.Post;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 22.0.2 (Oracle Corporation)"
)
@Component
public class PostMapperImpl implements PostMapper {

    @Override
    public PostResponse toPostResponse(Post post) {
        if ( post == null ) {
            return null;
        }

        PostResponse.PostResponseBuilder postResponse = PostResponse.builder();

        postResponse.id( post.getId() );
        postResponse.profileId( post.getProfileId() );
        postResponse.content( post.getContent() );
        List<String> list = post.getFileIds();
        if ( list != null ) {
            postResponse.fileIds( new ArrayList<String>( list ) );
        }
        List<String> list1 = post.getTags();
        if ( list1 != null ) {
            postResponse.tags( new ArrayList<String>( list1 ) );
        }
        postResponse.privacy( post.getPrivacy() );
        postResponse.point( post.getPoint() );
        postResponse.donationStartTime( post.getDonationStartTime() );
        postResponse.donationEndTime( post.getDonationEndTime() );
        postResponse.createdAt( post.getCreatedAt() );
        postResponse.updatedAt( post.getUpdatedAt() );

        return postResponse.build();
    }
}

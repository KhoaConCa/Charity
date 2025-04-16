package com.tuandanh.PostService.mapper;

import com.tuandanh.PostService.dto.response.PostResponse;
import com.tuandanh.PostService.entity.Post;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    comments = "version: 1.5.5.Final, compiler: Eclipse JDT (IDE) 3.42.0.z20250331-1358, environment: Java 21.0.6 (Eclipse Adoptium)"
)
@Component
public class PostMapperImpl implements PostMapper {

    @Override
    public PostResponse toPostResponse(Post post) {
        if ( post == null ) {
            return null;
        }

        PostResponse.PostResponseBuilder postResponse = PostResponse.builder();

        postResponse.content( post.getContent() );
        postResponse.createdAt( post.getCreatedAt() );
        List<String> list = post.getFileIds();
        if ( list != null ) {
            postResponse.fileIds( new ArrayList<String>( list ) );
        }
        postResponse.id( post.getId() );
        postResponse.point( post.getPoint() );
        postResponse.privacy( post.getPrivacy() );
        postResponse.profileId( post.getProfileId() );
        List<String> list1 = post.getTags();
        if ( list1 != null ) {
            postResponse.tags( new ArrayList<String>( list1 ) );
        }
        postResponse.updatedAt( post.getUpdatedAt() );

        return postResponse.build();
    }
}

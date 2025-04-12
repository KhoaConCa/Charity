package com.tuandanh.PostService.mapper;

import com.tuandanh.PostService.dto.Comment;
import com.tuandanh.PostService.dto.Reaction;
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

        List<Comment> list = post.getComments();
        if ( list != null ) {
            postResponse.comments( new ArrayList<Comment>( list ) );
        }
        postResponse.content( post.getContent() );
        postResponse.createdAt( post.getCreatedAt() );
        List<String> list1 = post.getFileIds();
        if ( list1 != null ) {
            postResponse.fileIds( new ArrayList<String>( list1 ) );
        }
        postResponse.point( post.getPoint() );
        postResponse.privacy( post.getPrivacy() );
        postResponse.profileId( post.getProfileId() );
        List<Reaction> list2 = post.getReactions();
        if ( list2 != null ) {
            postResponse.reactions( new ArrayList<Reaction>( list2 ) );
        }
        List<String> list3 = post.getTags();
        if ( list3 != null ) {
            postResponse.tags( new ArrayList<String>( list3 ) );
        }
        postResponse.updatedAt( post.getUpdatedAt() );

        return postResponse.build();
    }
}

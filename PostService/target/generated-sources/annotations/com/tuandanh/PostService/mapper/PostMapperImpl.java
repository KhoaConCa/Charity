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

        postResponse.profileId( post.getProfileId() );
        postResponse.content( post.getContent() );
        List<String> list = post.getFileIds();
        if ( list != null ) {
            postResponse.fileIds( new ArrayList<String>( list ) );
        }
        List<Reaction> list1 = post.getReactions();
        if ( list1 != null ) {
            postResponse.reactions( new ArrayList<Reaction>( list1 ) );
        }
        List<String> list2 = post.getTags();
        if ( list2 != null ) {
            postResponse.tags( new ArrayList<String>( list2 ) );
        }
        postResponse.privacy( post.getPrivacy() );
        postResponse.point( post.getPoint() );
        List<Comment> list3 = post.getComments();
        if ( list3 != null ) {
            postResponse.comments( new ArrayList<Comment>( list3 ) );
        }
        postResponse.createdAt( post.getCreatedAt() );
        postResponse.updatedAt( post.getUpdatedAt() );

        return postResponse.build();
    }
}

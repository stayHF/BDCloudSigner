# BDCloudSigner
A Baidu Cloud Servcies network request signer.

## How to use

```objc

#import "BDCloudSigner.h"

id<BDCloudSigner> createSigner() {
    BDCloudCredentials* credentials = [BDCloudCredentials new];
    credentials.accessKey = @"<access key>";
    credentials.secretKey = @"<secret key>";

    id<BDCloudSigner> signer = [[BDCloudAKSKSigner alloc] initWithCredentials:credentials];
    signer.expiredTimeInSeconds = 3600;

    return signer;
}

NSMutableURLRequest* createRequest() {
    // create url directly, or use NSURLComponents.
    NSURL* url = [NSURL URLWithString:@"http://bj.bcebos.com/v1/bucket/object?append"];

    // create request.
    NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    [request setValue:@"<length>" forHTTPHeaderField:@"Content-Length"];
    [request setValue:@"<md5>" forHTTPHeaderField:@"Content-MD5"];
    [request setValue:@"text/plain" forHTTPHeaderField:@"Content-Type"];

    // custom metadata key should begin with lower case prefix 'x-bce-'.
    [request setValue:@"2017-01-08T21:42:30Z" forHTTPHeaderField:@"x-bce-user-metadata-createtime"];

    // Host will be set when call sign.
    //[request setValue:@"bj.bcebos.com" forHTTPHeaderField:@"Host"];

    return request;
}

void sign() {
    id<BDCloudSigner> signer = createSigner();
    NSMutableURLRequest* request = createRequest();
    if (![signer sign:request]) {
        return;
    }

    // url
    NSURL* fileURL = [NSURL fileURLWithPath:@"<file path>"];

    // send request
    // sample purpose, don't care task will running correctly.
    [[NSURLSession sharedSession] uploadTaskWithRequest:request
                                               fromFile:fileURL];
}
```

Visit [Baidu Cloud Services auth Document](https://cloud.baidu.com/doc/Reference/AuthenticationMechanism.html).


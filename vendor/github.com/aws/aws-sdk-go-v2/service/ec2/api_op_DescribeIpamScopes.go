// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Get information about your IPAM scopes.
func (c *Client) DescribeIpamScopes(ctx context.Context, params *DescribeIpamScopesInput, optFns ...func(*Options)) (*DescribeIpamScopesOutput, error) {
	if params == nil {
		params = &DescribeIpamScopesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeIpamScopes", params, optFns, c.addOperationDescribeIpamScopesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeIpamScopesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeIpamScopesInput struct {

	// A check for whether you have the required permissions for the action without
	// actually making the request and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// One or more filters for the request. For more information about filtering, see [Filtering CLI output].
	//
	// [Filtering CLI output]: https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html
	Filters []types.Filter

	// The IDs of the scopes you want information on.
	IpamScopeIds []string

	// The maximum number of results to return in the request.
	MaxResults *int32

	// The token for the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeIpamScopesOutput struct {

	// The scopes you want information on.
	IpamScopes []types.IpamScope

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeIpamScopesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeIpamScopes{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeIpamScopes{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeIpamScopes"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeIpamScopes(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

// DescribeIpamScopesAPIClient is a client that implements the DescribeIpamScopes
// operation.
type DescribeIpamScopesAPIClient interface {
	DescribeIpamScopes(context.Context, *DescribeIpamScopesInput, ...func(*Options)) (*DescribeIpamScopesOutput, error)
}

var _ DescribeIpamScopesAPIClient = (*Client)(nil)

// DescribeIpamScopesPaginatorOptions is the paginator options for
// DescribeIpamScopes
type DescribeIpamScopesPaginatorOptions struct {
	// The maximum number of results to return in the request.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeIpamScopesPaginator is a paginator for DescribeIpamScopes
type DescribeIpamScopesPaginator struct {
	options   DescribeIpamScopesPaginatorOptions
	client    DescribeIpamScopesAPIClient
	params    *DescribeIpamScopesInput
	nextToken *string
	firstPage bool
}

// NewDescribeIpamScopesPaginator returns a new DescribeIpamScopesPaginator
func NewDescribeIpamScopesPaginator(client DescribeIpamScopesAPIClient, params *DescribeIpamScopesInput, optFns ...func(*DescribeIpamScopesPaginatorOptions)) *DescribeIpamScopesPaginator {
	if params == nil {
		params = &DescribeIpamScopesInput{}
	}

	options := DescribeIpamScopesPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeIpamScopesPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeIpamScopesPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeIpamScopes page.
func (p *DescribeIpamScopesPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeIpamScopesOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.NextToken = p.nextToken

	var limit *int32
	if p.options.Limit > 0 {
		limit = &p.options.Limit
	}
	params.MaxResults = limit

	result, err := p.client.DescribeIpamScopes(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.NextToken

	if p.options.StopOnDuplicateToken &&
		prevToken != nil &&
		p.nextToken != nil &&
		*prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opDescribeIpamScopes(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeIpamScopes",
	}
}

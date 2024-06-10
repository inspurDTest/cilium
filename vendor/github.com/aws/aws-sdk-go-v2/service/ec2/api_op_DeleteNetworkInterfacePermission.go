// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Deletes a permission for a network interface. By default, you cannot delete the
// permission if the account for which you're removing the permission has attached
// the network interface to an instance. However, you can force delete the
// permission, regardless of any attachment.
func (c *Client) DeleteNetworkInterfacePermission(ctx context.Context, params *DeleteNetworkInterfacePermissionInput, optFns ...func(*Options)) (*DeleteNetworkInterfacePermissionOutput, error) {
	if params == nil {
		params = &DeleteNetworkInterfacePermissionInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DeleteNetworkInterfacePermission", params, optFns, c.addOperationDeleteNetworkInterfacePermissionMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DeleteNetworkInterfacePermissionOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Contains the parameters for DeleteNetworkInterfacePermission.
type DeleteNetworkInterfacePermissionInput struct {

	// The ID of the network interface permission.
	//
	// This member is required.
	NetworkInterfacePermissionId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// Specify true to remove the permission even if the network interface is attached
	// to an instance.
	Force *bool

	noSmithyDocumentSerde
}

// Contains the output for DeleteNetworkInterfacePermission.
type DeleteNetworkInterfacePermissionOutput struct {

	// Returns true if the request succeeds, otherwise returns an error.
	Return *bool

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDeleteNetworkInterfacePermissionMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDeleteNetworkInterfacePermission{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDeleteNetworkInterfacePermission{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DeleteNetworkInterfacePermission"); err != nil {
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
	if err = addOpDeleteNetworkInterfacePermissionValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDeleteNetworkInterfacePermission(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opDeleteNetworkInterfacePermission(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DeleteNetworkInterfacePermission",
	}
}

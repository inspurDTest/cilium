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

// Registers members (network interfaces) with the transit gateway multicast
// group. A member is a network interface associated with a supported EC2 instance
// that receives multicast traffic. For information about supported instances, see [Multicast Consideration]
// in Amazon VPC Transit Gateways.
//
// After you add the members, use [SearchTransitGatewayMulticastGroups] to verify that the members were added to the
// transit gateway multicast group.
//
// [SearchTransitGatewayMulticastGroups]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SearchTransitGatewayMulticastGroups.html
// [Multicast Consideration]: https://docs.aws.amazon.com/vpc/latest/tgw/transit-gateway-limits.html#multicast-limits
func (c *Client) RegisterTransitGatewayMulticastGroupMembers(ctx context.Context, params *RegisterTransitGatewayMulticastGroupMembersInput, optFns ...func(*Options)) (*RegisterTransitGatewayMulticastGroupMembersOutput, error) {
	if params == nil {
		params = &RegisterTransitGatewayMulticastGroupMembersInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "RegisterTransitGatewayMulticastGroupMembers", params, optFns, c.addOperationRegisterTransitGatewayMulticastGroupMembersMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*RegisterTransitGatewayMulticastGroupMembersOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type RegisterTransitGatewayMulticastGroupMembersInput struct {

	// The group members' network interface IDs to register with the transit gateway
	// multicast group.
	//
	// This member is required.
	NetworkInterfaceIds []string

	// The ID of the transit gateway multicast domain.
	//
	// This member is required.
	TransitGatewayMulticastDomainId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The IP address assigned to the transit gateway multicast group.
	GroupIpAddress *string

	noSmithyDocumentSerde
}

type RegisterTransitGatewayMulticastGroupMembersOutput struct {

	// Information about the registered transit gateway multicast group members.
	RegisteredMulticastGroupMembers *types.TransitGatewayMulticastRegisteredGroupMembers

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationRegisterTransitGatewayMulticastGroupMembersMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpRegisterTransitGatewayMulticastGroupMembers{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpRegisterTransitGatewayMulticastGroupMembers{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "RegisterTransitGatewayMulticastGroupMembers"); err != nil {
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
	if err = addOpRegisterTransitGatewayMulticastGroupMembersValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opRegisterTransitGatewayMulticastGroupMembers(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opRegisterTransitGatewayMulticastGroupMembers(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "RegisterTransitGatewayMulticastGroupMembers",
	}
}

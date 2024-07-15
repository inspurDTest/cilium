package genericdevice

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
	"github.com/google/uuid"

	"github.com/cilium/cilium/plugins/cilium-cni/types"
	cniTypes "github.com/containernetworking/cni/pkg/types"

	"github.com/cilium/cilium/pkg/client"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging/logfields"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
)

type GenericDeviceChainer struct{}

func (f *GenericDeviceChainer) ImplementsAdd() bool {
	return true
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-generic-device")
)

func (f *GenericDeviceChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) (res *cniTypesVer.Result, err error) {
	logger := log.WithField("eventUUID", uuid.New())
	logger.Debug("Enter Add on Generic-device")
	err = cniVersion.ParsePrevResult(&pluginCtx.NetConf.NetConf)
	if err != nil {
		err = fmt.Errorf("unable to understand network config: %s", err)
		return
	}

	var prevRes *cniTypesVer.Result
	prevRes, err = cniTypesVer.NewResultFromResult(pluginCtx.NetConf.PrevResult)
	if err != nil {
		err = fmt.Errorf("unable to get previous network result: %s", err)
		return
	}
	logger.Debugf("This is a test message in generic-device,###############")
	logger.Debugf("Processing prevRes: %#v", prevRes)
	logger.Debugf("interfaces length: %v", prevRes.Interfaces)
	for _, item := range prevRes.Interfaces {
		logger.Debugf("interface name: %v,sandbox:%v,mac:%v", item.Name, item.Sandbox, item.Mac)
	}
	logger.Debugf("Processing pluginCtx.Args in generic-device: %#v", pluginCtx.Args)
	n, err := types.LoadNetConf(pluginCtx.Args.StdinData)
	if err != nil {
		logger.Debugf("Load args failed ")
		return
	}
	logger.Debugf("Processing CNI NetConf in generic-device: %#v", n)
	defer func() {
		if err != nil {
			pluginCtx.Logger.WithError(err).
				WithFields(logrus.Fields{"cni-pre-result": pluginCtx.NetConf.PrevResult}).
				Errorf("Unable to create endpoint")
		}
	}()
	var (
		deviceName, deviceMac, deviceIP, deviceIPv6 string
		netNS                                       ns.NetNS
	)

	if pluginCtx.Args.Netns == "" {
		err = errors.New("unable to determine Netns")
		return
	}
	for _, inf := range prevRes.Interfaces {
		if inf.Sandbox == pluginCtx.Args.Netns {
			deviceName = inf.Name
			break
		}
	}

	netNS, err = ns.GetNS(pluginCtx.Args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %s", pluginCtx.Args.Netns, err)
		return
	}
	defer netNS.Close()
	logger.Debugf("Processing NetNs: %#v", netNS)

	if deviceName == "" {
		err = fmt.Errorf("unable to find interface in network namespace %v", pluginCtx.Args.Netns)
		return
	}

	netNS, err = ns.GetNS(pluginCtx.Args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %s", pluginCtx.Args.Netns, err)
		return
	}
	defer netNS.Close()

	if err = netNS.Do(func(_ ns.NetNS) error {
		links, err := netlink.LinkList()
		logger.Debugf("Links in NetNs: %#v", links)
		if err != nil {
			return fmt.Errorf("failed to list link %s", pluginCtx.Args.Netns)
		}
		for _, link := range links {
			if link.Attrs().Name != deviceName {
				continue
			}
			deviceMac = link.Attrs().HardwareAddr.String()

			addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err != nil {
				return fmt.Errorf("unable to list addresses for link %s: %s", link.Attrs().Name, err)
			}
			if len(addrs) < 1 {
				return fmt.Errorf("no address configured inside container")
			}

			addrsv6, err := netlink.AddrList(link, netlink.FAMILY_V6)
			if err == nil && len(addrsv6) > 0 {
				deviceIPv6 = addrsv6[0].IPNet.IP.String()
			} else if err != nil {
				pluginCtx.Logger.WithError(err).WithFields(logrus.Fields{
					logfields.Interface: link.Attrs().Name}).Warn("No valid IPv6 address found")
			}

			deviceIP = addrs[0].IPNet.IP.String()
			return nil
		}

		return fmt.Errorf("no link found inside container")
	}); err != nil {
		return
	}

	switch {
	case deviceMac == "":
		err = errors.New("unable to determine device MAC address")
		return
	case deviceIP == "" && deviceIPv6 == "":
		err = errors.New("unable to determine device IP address")
		return
	}

	var disabled = false
	ep := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: deviceIP,
			IPV6: deviceIPv6,
		},
		ContainerID:       pluginCtx.Args.ContainerID,
		State:             models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		NetNs:             pluginCtx.Args.Netns,
		Mac:               deviceMac,
		HostMac:           deviceMac,
		InterfaceName:     deviceName,
		K8sPodName:        string(pluginCtx.CniArgs.K8S_POD_NAME),
		K8sNamespace:      string(pluginCtx.CniArgs.K8S_POD_NAMESPACE),
		SyncBuildEndpoint: true,
		DatapathConfiguration: &models.EndpointDatapathConfiguration{
			RequireArpPassthrough: true,
			RequireEgressProg:     true,
			ExternalIpam:          true,
			RequireRouting:        &disabled,
		},
	}
	logger.Debugf("Endpoint %s: %+v", ep.ContainerID, ep)
	err = cli.EndpointCreate(ep)
	if err != nil {
		pluginCtx.Logger.WithError(err).WithFields(logrus.Fields{
			logfields.ContainerID: ep.ContainerID}).Warn("Unable to create endpoint")
		err = fmt.Errorf("unable to create endpoint: %s", err)
		return
	}

	pluginCtx.Logger.WithFields(logrus.Fields{
		logfields.ContainerID: ep.ContainerID}).Debug("Endpoint successfully created")

	res = prevRes

	return
}

func (f *GenericDeviceChainer) ImplementsDelete() bool {
	return true
}

func (f *GenericDeviceChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext, delClient *lib.DeletionFallbackClient) (err error) {
	id := endpointid.NewID(endpointid.ContainerIdPrefix, pluginCtx.Args.ContainerID)
	if err := delClient.EndpointDelete(id); err != nil {
		pluginCtx.Logger.WithError(err).Warning("Errors encountered while deleting endpoint")
	}
	return nil
}

func (f *GenericDeviceChainer) Check(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) error {
	// Just confirm that the endpoint is healthy
	eID := fmt.Sprintf("container-id:%s", pluginCtx.Args.ContainerID)
	pluginCtx.Logger.Debugf("Asking agent for healthz for %s", eID)
	epHealth, err := cli.EndpointHealthGet(eID)
	if err != nil {
		return cniTypes.NewError(types.CniErrHealthzGet, "HealthzFailed",
			fmt.Sprintf("failed to retrieve container health: %s", err))
	}

	if epHealth.OverallHealth == models.EndpointHealthStatusFailure {
		return cniTypes.NewError(types.CniErrUnhealthy, "Unhealthy",
			"container is unhealthy in agent")
	}
	pluginCtx.Logger.Debugf("Container %s has a healthy agent endpoint", pluginCtx.Args.ContainerID)
	return nil
}

func init() {
	chainingapi.Register("generic-device", &GenericDeviceChainer{})
}

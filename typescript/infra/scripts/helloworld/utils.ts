import {
  HelloMultiProtocolApp,
  HelloWorldApp,
  helloWorldFactories,
} from '@hyperlane-xyz/helloworld';
import {
  AgentConnectionType,
  HyperlaneCore,
  HyperlaneIgp,
  MultiProtocolCore,
  MultiProtocolProvider,
  MultiProvider,
  attachContractsMap,
  chainMetadata,
  filterAddressesToProtocol,
  hyperlaneEnvironments,
  igpFactories,
} from '@hyperlane-xyz/sdk';
import { hyperlaneEnvironmentsWithSealevel } from '@hyperlane-xyz/sdk/src';
import { ProtocolType } from '@hyperlane-xyz/utils';

import { Contexts } from '../../config/contexts';
import { EnvironmentConfig } from '../../src/config';
import { deployEnvToSdkEnv } from '../../src/config/environment';
import { HelloWorldConfig } from '../../src/config/helloworld';
import { Role } from '../../src/roles';

export async function getHelloWorldApp(
  coreConfig: EnvironmentConfig,
  context: Contexts,
  keyRole: Role,
  keyContext: Contexts = context,
  connectionType: AgentConnectionType = AgentConnectionType.Http,
) {
  const multiProvider: MultiProvider = await coreConfig.getMultiProvider(
    keyContext,
    keyRole,
    connectionType,
  );
  const helloworldConfig = getHelloWorldConfig(coreConfig, context);
  const contracts = attachContractsMap(
    helloworldConfig.addresses,
    helloWorldFactories,
  );
  const core = HyperlaneCore.fromEnvironment(
    deployEnvToSdkEnv[coreConfig.environment],
    multiProvider,
  );
  return new HelloWorldApp(core, contracts, multiProvider);
}

export async function getHelloWorldMultiProtocolApp(
  coreConfig: EnvironmentConfig,
  context: Contexts,
  keyRole: Role,
  keyContext: Contexts = context,
  connectionType: AgentConnectionType = AgentConnectionType.Http,
) {
  const multiProvider: MultiProvider = await coreConfig.getMultiProvider(
    keyContext,
    keyRole,
    connectionType,
  );
  const sdkEnvName = deployEnvToSdkEnv[coreConfig.environment];
  const keys = await coreConfig.getKeys(keyContext, keyRole);

  const helloworldConfig = getHelloWorldConfig(coreConfig, context);

  const multiProtocolProvider =
    MultiProtocolProvider.fromMultiProvider(multiProvider);
  // Hacking around infra code limitations, we may need to add solana manually
  // because the it's not in typescript/infra/config/environments/testnet3/chains.ts
  // Adding it there breaks many things
  if (!multiProtocolProvider.getKnownChainNames().includes('solanadevnet')) {
    multiProtocolProvider.addChain(chainMetadata.solanadevnet);
  }
  // Add the helloWorld contract addresses to the metadata
  const mpWithHelloWorld = multiProtocolProvider.extendChainMetadata(
    helloworldConfig.addresses,
  );

  const core = MultiProtocolCore.fromAddressesMap(
    hyperlaneEnvironmentsWithSealevel[sdkEnvName],
    multiProtocolProvider,
  );

  // Extend the MP with mailbox addresses because the sealevel
  // adapter needs that to function
  const mpWithMailbox = mpWithHelloWorld.extendChainMetadata(core.chainMap);
  const app = new HelloMultiProtocolApp(mpWithMailbox);

  // TODO we need a MultiProtocolIgp
  // Using an standard IGP for just evm chains for now
  // Unfortunately this requires hacking surgically around certain addresses
  const envAddresses = hyperlaneEnvironments[sdkEnvName];
  const filteredAddresses = filterAddressesToProtocol(
    envAddresses,
    ProtocolType.Ethereum,
    multiProtocolProvider,
  );
  const contractsMap = attachContractsMap(filteredAddresses, igpFactories);
  const igp = new HyperlaneIgp(contractsMap, multiProvider);

  return { app, core, igp, multiProvider, multiProtocolProvider, keys };
}

export function getHelloWorldConfig(
  coreConfig: EnvironmentConfig,
  context: Contexts,
): HelloWorldConfig {
  const helloWorldConfigs = coreConfig.helloWorld;
  if (!helloWorldConfigs) {
    throw new Error(
      `Environment ${coreConfig.environment} does not have a HelloWorld config`,
    );
  }
  const config = helloWorldConfigs[context];
  if (!config) {
    throw new Error(`Context ${context} does not have a HelloWorld config`);
  }
  return config;
}

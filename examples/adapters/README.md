# Adapter starters

These are **starter-generation recipes**, not pre-certified adapters.

The provider/runtime mappings come from
`asimov_conformance/adapter_catalog.json`. Generate a local starter with Studio
or the CLI, then wire the real controls and run `asimov doctor`.

## Studio

```bash
asimov studio
```

Open **Adapter Assistant**, choose your stack, and select **Generate starter
adapter**.

## CLI recipes

### OpenAI Agents API

```bash
asimov adapter-scaffold \
  --runtime openai-agents-api \
  --output ./openai-agents-api-adapter
```

### OpenAI Agents SDK

```bash
asimov adapter-scaffold \
  --runtime openai-agents-sdk \
  --output ./openai-agents-sdk-adapter
```

### OpenAI Responses / custom loop

```bash
asimov adapter-scaffold \
  --runtime openai-responses-custom \
  --output ./openai-responses-adapter
```

### Claude Managed Agents

```bash
asimov adapter-scaffold \
  --runtime anthropic-managed-agents \
  --output ./claude-managed-adapter
```

### Claude Agent SDK

```bash
asimov adapter-scaffold \
  --runtime claude-agent-sdk \
  --output ./claude-agent-sdk-adapter
```

### Claude Messages API / custom loop

```bash
asimov adapter-scaffold \
  --runtime anthropic-messages-custom \
  --output ./claude-messages-adapter
```

### Amazon Bedrock AgentCore Runtime

```bash
asimov adapter-scaffold \
  --runtime aws-agentcore-runtime \
  --hosting aws \
  --authority aws-iam \
  --output ./aws-agentcore-adapter
```

### Google ADK

```bash
asimov adapter-scaffold \
  --runtime google-adk \
  --hosting gcp \
  --authority gcp-iam \
  --output ./google-adk-adapter
```

### Google managed Agent Runtime

```bash
asimov adapter-scaffold \
  --runtime google-agent-runtime \
  --hosting gcp \
  --authority gcp-iam \
  --output ./google-agent-runtime-adapter
```

### Microsoft Agent Framework

```bash
asimov adapter-scaffold \
  --runtime microsoft-agent-framework \
  --hosting azure \
  --authority azure-entra-rbac \
  --output ./microsoft-agent-framework-adapter
```

### Microsoft Foundry Agent Service

```bash
asimov adapter-scaffold \
  --runtime microsoft-foundry-agent-service \
  --hosting azure \
  --authority azure-entra-rbac \
  --output ./foundry-agent-adapter
```

### LangGraph / LangChain agents

```bash
asimov adapter-scaffold \
  --runtime langgraph \
  --output ./langgraph-adapter
```

### CrewAI

```bash
asimov adapter-scaffold \
  --runtime crewai \
  --output ./crewai-adapter
```

### Custom/local open-weight stack

```bash
asimov adapter-scaffold \
  --runtime custom-local \
  --hosting local-process \
  --output ./local-agent-adapter
```

## Compose the real stack

Add hosting, authority, resource, evidence, and integration selections as they
apply. Example:

```bash
asimov adapter-scaffold \
  --runtime langgraph \
  --hosting kubernetes \
  --authority aws-iam \
  --resource postgresql \
  --resource queue \
  --evidence opentelemetry \
  --evidence cloud-audit \
  --evidence resource-audit \
  --integration mcp \
  --output ./asimov-adapter
```

The generated directory contains:

```text
adapter.py
README.md
asimov-adapter.json
```

The initial `capabilities()` result is deliberately empty. Do not add a
capability merely because the chosen framework has a similarly named feature.
Implement the actual deployment surface, test it, then add the capability and
rerun `asimov doctor`.

For deeper guidance, see
[Provider & Stack Guide](../../docs/ADAPTER-PROVIDERS.md).

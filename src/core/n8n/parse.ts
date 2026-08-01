import type {
  ConnectionEdge,
  JsonObject,
  N8nNode,
  NormalizedWorkflow,
  ParserWarning,
  RawN8nConnectionTarget,
  RawN8nWorkflow,
} from './types'

function isRecord(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value : undefined
}

function normalizeNode(rawNode: unknown, index: number, warnings: ParserWarning[]): N8nNode | null {
  if (!isRecord(rawNode)) {
    warnings.push({
      code: 'invalid_shape',
      message: `Node at position ${index + 1} is not an object.`,
    })
    return null
  }

  const name = asString(rawNode.name) ?? `Unnamed node ${index + 1}`
  const type = asString(rawNode.type) ?? 'unknown'

  if (!asString(rawNode.name)) {
    warnings.push({
      code: 'missing_node_name',
      message: `Node at position ${index + 1} is missing a name.`,
      nodeName: name,
    })
  }

  if (!asString(rawNode.type)) {
    warnings.push({
      code: 'missing_node_type',
      message: `${name} is missing a node type.`,
      nodeName: name,
    })
  }

  return {
    id: asString(rawNode.id) ?? name,
    name,
    type,
    typeVersion: asNumber(rawNode.typeVersion),
    parameters: isRecord(rawNode.parameters) ? rawNode.parameters : {},
    credentials: isRecord(rawNode.credentials) ? rawNode.credentials : {},
    disabled: rawNode.disabled === true,
    retryOnFail: rawNode.retryOnFail === true,
    maxTries: asNumber(rawNode.maxTries),
    waitBetweenTries: asNumber(rawNode.waitBetweenTries),
    continueOnFail: rawNode.continueOnFail === true,
    onError: asString(rawNode.onError),
    notes: asString(rawNode.notes),
    raw: rawNode,
  }
}

function isConnectionTarget(value: unknown): value is RawN8nConnectionTarget & { node: string } {
  return isRecord(value) && typeof value.node === 'string'
}

function normalizeConnections(
  workflow: RawN8nWorkflow,
  nodeIdByName: Record<string, string>,
  nodeById: Record<string, N8nNode>,
  warnings: ParserWarning[],
): ConnectionEdge[] {
  if (!isRecord(workflow.connections)) {
    warnings.push({
      code: 'missing_connections',
      message: 'Workflow has no connections object.',
    })
    return []
  }

  const edges: ConnectionEdge[] = []

  for (const [sourceName, outputsByType] of Object.entries(workflow.connections)) {
    const sourceId = nodeIdByName[sourceName]
    const sourceNode = sourceId ? nodeById[sourceId] : undefined

    if (!sourceNode) {
      warnings.push({
        code: 'missing_connection_source',
        message: `Connection source "${sourceName}" does not match a workflow node.`,
        nodeName: sourceName,
      })
      continue
    }

    if (!isRecord(outputsByType)) {
      warnings.push({
        code: 'unsupported_connection_shape',
        message: `Connections for "${sourceName}" have an unsupported shape.`,
        nodeName: sourceName,
      })
      continue
    }

    for (const [outputType, outputGroups] of Object.entries(outputsByType)) {
      if (!Array.isArray(outputGroups)) {
        warnings.push({
          code: 'unsupported_connection_shape',
          message: `Connection output "${outputType}" for "${sourceName}" is not an array.`,
          nodeName: sourceName,
        })
        continue
      }

      outputGroups.forEach((targets, outputIndex) => {
        if (!Array.isArray(targets)) {
          warnings.push({
            code: 'unsupported_connection_shape',
            message: `Connection group ${outputIndex + 1} for "${sourceName}" is not an array.`,
            nodeName: sourceName,
          })
          return
        }

        targets.forEach((target, fallbackInputIndex) => {
          if (!isConnectionTarget(target)) {
            warnings.push({
              code: 'unsupported_connection_shape',
              message: `A connection target from "${sourceName}" is missing a node name.`,
              nodeName: sourceName,
            })
            return
          }

          const targetId = nodeIdByName[target.node]
          const targetNode = targetId ? nodeById[targetId] : undefined

          if (!targetNode) {
            warnings.push({
              code: 'missing_connection_target',
              message: `Connection target "${target.node}" does not match a workflow node.`,
              nodeName: target.node,
            })
            return
          }

          edges.push({
            sourceId: sourceNode.id,
            sourceName: sourceNode.name,
            targetId: targetNode.id,
            targetName: targetNode.name,
            outputType,
            outputIndex,
            inputIndex: typeof target.index === 'number' ? target.index : fallbackInputIndex,
          })
        })
      })
    }
  }

  return edges
}

export function parseWorkflow(raw: unknown): NormalizedWorkflow {
  const warnings: ParserWarning[] = []
  const rawText = safeStringify(raw)
  raw = unwrapWorkflowEnvelope(raw, warnings)

  if (!isRecord(raw)) {
    warnings.push({
      code: 'invalid_shape',
      message: 'Workflow JSON must be an object.',
    })
    return {
      name: 'Invalid workflow',
      nodes: [],
      nodeById: {},
      nodeIdByName: {},
      edges: [],
      warnings,
      raw: {},
      rawText,
    }
  }

  const workflow = raw as RawN8nWorkflow
  const rawNodes = Array.isArray(workflow.nodes) ? workflow.nodes : []

  if (!Array.isArray(workflow.nodes)) {
    warnings.push({
      code: 'missing_nodes',
      message: 'Workflow is missing a nodes array.',
    })
  } else if (rawNodes.length === 0) {
    warnings.push({
      code: 'empty_nodes',
      message: 'Workflow has no nodes.',
    })
  }

  const nodes = rawNodes
    .map((node, index) => normalizeNode(node, index, warnings))
    .filter((node): node is N8nNode => node !== null)

  const nodeById: Record<string, N8nNode> = {}
  const nodeIdByName: Record<string, string> = {}

  for (const node of nodes) {
    if (nodeById[node.id]) {
      node.id = `${node.id}-${Object.keys(nodeById).length + 1}`
    }

    if (nodeIdByName[node.name]) {
      warnings.push({
        code: 'duplicate_node_name',
        message: `Duplicate node name "${node.name}" can make n8n connections ambiguous.`,
        nodeName: node.name,
      })
    }

    nodeById[node.id] = node
    nodeIdByName[node.name] = node.id
  }

  return {
    id: asString(workflow.id),
    name: asString(workflow.name) ?? 'Untitled workflow',
    nodes,
    nodeById,
    nodeIdByName,
    edges: normalizeConnections(workflow, nodeIdByName, nodeById, warnings),
    warnings,
    raw: workflow,
    rawText,
  }
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value)
  } catch {
    return ''
  }
}

function unwrapWorkflowEnvelope(raw: unknown, warnings: ParserWarning[]): unknown {
  if (Array.isArray(raw)) {
    const firstWorkflow = raw.find((item) => isRecord(item) && Array.isArray(item.nodes))
    if (firstWorkflow) {
      warnings.push({
        code: 'invalid_shape',
        message: `Found ${raw.length} workflow-like items; scanned the first workflow only.`,
      })
      return firstWorkflow
    }
    return raw
  }

  if (isRecord(raw) && Array.isArray(raw.data)) {
    const firstWorkflow = raw.data.find((item) => isRecord(item) && Array.isArray(item.nodes))
    if (firstWorkflow) {
      warnings.push({
        code: 'invalid_shape',
        message: 'Found a data array wrapper; scanned the first workflow in data.',
      })
      return firstWorkflow
    }
  }

  return raw
}

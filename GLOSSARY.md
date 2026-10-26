# Ubuntu Fleet Manager

Ubuntu Fleet Manager gives an operator a controlled way to inspect and administer enrolled Ubuntu hosts through MCP.

## People and boundaries

**Operator**:
A person who configures the fleet and authorizes administration.

**Personal tenant**:
The private scope owned by one operator. It contains that operator's enrolled hosts, actions, and audit records.

**Managed host**:
An Ubuntu system enrolled for remote administration.

**Host agent**:
The local service on a managed host that reports host state and performs authorized operations.

**Control plane**:
The service that authenticates operators, tracks enrolled hosts, schedules operations, and returns results.

## Enrollment and execution

**Pairing code**:
A temporary one-use value that lets an operator enroll a host.

**Host credential**:
A revocable credential that identifies one enrolled host to the control plane.

**Operation**:
A request to inspect or change a managed host.

**Job**:
An operation assigned to a host agent for execution.

**Lease**:
A temporary claim on a job that prevents multiple agents from executing it concurrently.

**Typed action**:
An operation with a bounded input and output shape and known effects.

**Reversal**:
A compensating operation that attempts to restore the state captured before a supported typed action.

**Approval**:
Explicit human authorization for an operation that can change host state.

## Accountability

**Audit record**:
A record of who requested an operation, which host it targeted, its approval and result, and whether reversal remains available.

**Retention window**:
The configured period during which full audit and reversal information remains available.

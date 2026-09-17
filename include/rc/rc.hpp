#pragma once

// Route Convergence 1.0.0 - deterministic route-transition ordering,
// dependency-safe state change and convergence-governance runtime.
//
// This umbrella header pulls in the complete public control-plane API.  The
// networked runtime (coordinator server, client, transport and local process
// supervision) lives in <rc/net.hpp>, <rc/server.hpp>, <rc/client.hpp> and
// <rc/process.hpp>.

#include "rc/authority.hpp"
#include "rc/backend.hpp"
#include "rc/bytes.hpp"
#include "rc/convergence.hpp"
#include "rc/digest.hpp"
#include "rc/graph.hpp"
#include "rc/identity.hpp"
#include "rc/lifecycle.hpp"
#include "rc/limits.hpp"
#include "rc/outcome.hpp"
#include "rc/persistence.hpp"
#include "rc/plan.hpp"
#include "rc/policy.hpp"
#include "rc/protocol.hpp"
#include "rc/step.hpp"
#include "rc/synthetic.hpp"
#include "rc/upstream.hpp"
#include "rc/version.hpp"

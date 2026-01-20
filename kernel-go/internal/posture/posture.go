// WHY: Posture levels provide graduated constraint - higher posture
// means more restrictions, not more freedom. This inverts the traditional
// privilege escalation model.
package posture

const (
	// P0 is undefined/unknown - fails closed for high-risk operations
	P0 = 0

	// P1 is the default restrictive posture
	P1 = 1

	// P2 allows moderate operations with confirmation
	P2 = 2

	// P3 is high-autonomy mode with tighter constraint
	P3 = 3

	// P4 is maximum constraint mode (oracle/read-only)
	P4 = 4
)

// PostureLevel represents the current system posture
type PostureLevel int

// IsValid checks if a posture level is defined
func IsValid(level int) bool {
	return level >= P1 && level <= P4
}

// RequiresConfirmation determines if an operation at this posture needs user confirmation
func RequiresConfirmation(level int, operationRisk string) bool {
	// P0 is undefined - always require confirmation for any risk
	if level == P0 {
		return true
	}

	// Higher postures have more restrictions
	switch operationRisk {
	case "high":
		return level >= P2
	case "medium":
		return level >= P3
	case "low":
		return level >= P4
	default:
		return true // unknown risk - fail closed
	}
}

// FailClosed returns true if this posture should fail-closed for high-risk ops
func FailClosed(level int, operationRisk string) bool {
	// Undefined posture fails closed for high-risk
	if level == P0 && operationRisk == "high" {
		return true
	}
	return false
}

// State tracks posture transitions
type State struct {
	CurrentLevel int
	History      []Transition
}

// Transition records a posture change
type Transition struct {
	Timestamp int64
	FromLevel int
	ToLevel   int
	Reason    string
}

// NewState creates a new posture state with default P1 level
func NewState() *State {
	return &State{
		CurrentLevel: P1,
		History:      []Transition{},
	}
}

// SetLevel changes the posture level and records the transition
func (s *State) SetLevel(newLevel int, reason string) {
	transition := Transition{
		Timestamp: currentTimestamp(),
		FromLevel: s.CurrentLevel,
		ToLevel:   newLevel,
		Reason:    reason,
	}
	s.History = append(s.History, transition)
	s.CurrentLevel = newLevel
}

func currentTimestamp() int64 {
	// Simple timestamp - in production would use time.Now().Unix()
	return 0
}

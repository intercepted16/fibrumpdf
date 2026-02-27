package geometry

type Point struct{ X, Y float32 }

type Rect struct{ X0, Y0, X1, Y1 float32 }

var Empty = Rect{}

func (r Rect) IsEmpty() bool   { return r.X0 >= r.X1 || r.Y0 >= r.Y1 }
func (r Rect) Width() float32  { return r.X1 - r.X0 }
func (r Rect) Height() float32 { return r.Y1 - r.Y0 }

func (r Rect) Area() float32 {
	if r.IsEmpty() {
		return 0
	}
	return r.Width() * r.Height()
}

func (r Rect) Union(other Rect) Rect {
	if r.IsEmpty() {
		return other
	}
	if other.IsEmpty() {
		return r
	}
	return Rect{Min32(r.X0, other.X0), Min32(r.Y0, other.Y0), Max32(r.X1, other.X1), Max32(r.Y1, other.Y1)}
}

func (r Rect) Intersect(other Rect) Rect {
	result := Rect{Max32(r.X0, other.X0), Max32(r.Y0, other.Y0), Min32(r.X1, other.X1), Min32(r.Y1, other.Y1)}
	if result.IsEmpty() {
		return Empty
	}
	return result
}

func (r Rect) IntersectArea(other Rect) float32 { return r.Intersect(other).Area() }

func Min32(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}

func Max32(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}

func Abs32(x float32) float32 {
	if x < 0 {
		return -x
	}
	return x
}

func Clamp(x, lo, hi int) int {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func MergeNearby(positions []float32, tol float32) []float32 {
	if len(positions) < 2 {
		return positions
	}
	var result []float32
	result = append(result, positions[0])
	for i := 1; i < len(positions); i++ {
		if positions[i]-result[len(result)-1] > tol {
			result = append(result, positions[i])
		}
	}
	return result
}


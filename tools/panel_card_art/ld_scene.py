"""Leviton load center parts, modelled from Leviton's straight-on catalog photographs.

Units are inches. A breaker is built upright: +X right, +Y toward the logo end,
+Z out of the panel toward the viewer. `d` is the distance down from the top of the
raised face, which is how the photos were measured.

Run inside Blender:  blender -b --factory-startup --python ld_scene.py -- <job.json>
"""

import json
import math
import os
import sys
from math import atan2, cos, radians, sin, sqrt, tan

import bmesh
import bpy
from mathutils import Matrix, Vector

# The legends are set in Arial, which is close to what Leviton prints. Set
# LD_FONT_DIR if it isn't in one of the usual places.
FONT_FILES = {
    "regular": ("Arial.ttf", "arial.ttf"),
    "bold": ("Arial Bold.ttf", "arialbd.ttf", "Arial_Bold.ttf"),
    "narrow": ("Arial Narrow.ttf", "ARIALN.TTF", "arialn.ttf"),
}
FONT_DIRS = [
    os.environ.get("LD_FONT_DIR", ""),
    "/System/Library/Fonts/Supplemental",
    "/Library/Fonts",
    "C:/Windows/Fonts",
    "/usr/share/fonts/truetype/msttcorefonts",
]


def _find_font(names):
    for folder in FONT_DIRS:
        for name in names:
            path = os.path.join(folder, name)
            if folder and os.path.exists(path):
                return path
    raise SystemExit("Arial not found (%s). Set LD_FONT_DIR to the folder that has it." % names[0])


FONTS = {key: _find_font(names) for key, names in FONT_FILES.items()}

# The breakers carry the maker's name, as the real ones do (a plain bold
# grotesque, not Leviton's artwork). LD_NO_BRAND=1 renders them without it.
BRAND = not os.environ.get("LD_NO_BRAND")

# ---- measured from the catalog photos (inches) --------------------------------
PITCH = 1.0  # one breaker space
BODY_W = 0.98
FACE_W = 0.904  # raised face
FACE_L = 2.866
STEP_TOP = 0.44  # lower shelf above the raised face (logo end)
STEP_BOT = 0.33
FACE_H = 0.11  # raised face height above the shelves
CAV_X = 0.282  # handle opening half width
CAV_D0, CAV_D1 = 0.374, 1.441
PIVOT_D = (CAV_D0 + CAV_D1) / 2
PIVOT_Z = -0.085
BARREL_R = 0.340
EAR_X = 0.470
LIP_X = 0.274
ALPHA = radians(20.0)  # rocker travel each side of centre
SEAM = 0.0027  # half the visible gap between the two housing halves

FLAG = {
    "on": (0.004, 0.30, 0.115),
    "off": (0.86, 0.86, 0.85),
    "trip": (0.78, 0.030, 0.018),
}
HANDLE_ANGLE = {"on": ALPHA, "off": -ALPHA, "trip": 0.0}


def fy(d):
    """Photo distance `d` down the raised face -> model Y."""
    return FACE_L / 2 - d


# ---- scene helpers -------------------------------------------------------------
def reset_scene():
    bpy.ops.wm.read_factory_settings(use_empty=True)
    _MATS.clear()
    _FONT_CACHE.clear()
    _CAP.clear()
    scene = bpy.context.scene
    scene.render.engine = "CYCLES"
    scene.cycles.device = "CPU"
    scene.cycles.use_denoising = True
    scene.cycles.use_adaptive_sampling = True
    scene.cycles.adaptive_threshold = 0.005
    scene.cycles.max_bounces = 8
    scene.cycles.diffuse_bounces = 5
    scene.cycles.glossy_bounces = 4
    scene.cycles.pixel_filter_type = "BLACKMAN_HARRIS"
    scene.cycles.filter_width = 1.5
    scene.view_settings.view_transform = "Standard"
    scene.view_settings.look = "None"
    scene.view_settings.exposure = EXPOSURE
    scene.view_settings.gamma = 1.0
    tone_curve(scene)
    scene.render.image_settings.file_format = "PNG"
    scene.render.image_settings.color_mode = "RGBA"
    scene.render.image_settings.color_depth = "8"
    scene.render.image_settings.compression = 60
    return scene


EXPOSURE = 0.22  # stops; white painted steel should read as white, not grey
TONE_WHITE = 2.0
TONE = [(0.50, 0.50), (0.65, 0.640), (0.80, 0.755), (0.95, 0.835), (1.10, 0.885), (1.30, 0.930), (1.60, 0.972)]


def tone_curve(scene):
    """A gentle shoulder, as a camera gives: highlights roll off instead of clipping."""
    vs = scene.view_settings
    vs.use_curve_mapping = True
    cm = vs.curve_mapping
    cm.use_clip = False
    cm.extend = "HORIZONTAL"
    cm.black_level = (0.0, 0.0, 0.0)
    cm.white_level = (TONE_WHITE, TONE_WHITE, TONE_WHITE)
    curve = cm.curves[3]
    curve.points[0].location = (0.0, 0.0)
    curve.points[1].location = (1.0, 1.0)
    for x, y in TONE:
        curve.points.new(x / TONE_WHITE, y)
    cm.update()


def link(ob, parent=None):
    bpy.context.scene.collection.objects.link(ob)
    if parent is not None:
        ob.parent = parent
    return ob


def empty(name, loc=(0, 0, 0), parent=None):
    ob = bpy.data.objects.new(name, None)
    ob.location = loc
    return link(ob, parent)


_MATS = {}


def material(name, base, rough=0.4, spec=0.5, emission=None, strength=0.0, sss=0.0, coat=0.0):
    if name in _MATS:
        return _MATS[name]
    mat = bpy.data.materials.new(name)
    mat.use_nodes = True
    bsdf = mat.node_tree.nodes["Principled BSDF"]
    bsdf.inputs["Base Color"].default_value = (*base, 1.0)
    bsdf.inputs["Roughness"].default_value = rough
    bsdf.inputs["Specular IOR Level"].default_value = spec
    bsdf.inputs["IOR"].default_value = 1.49
    if sss:
        bsdf.inputs["Subsurface Weight"].default_value = sss
        bsdf.inputs["Subsurface Radius"].default_value = (1.0, 1.0, 1.0)
        bsdf.inputs["Subsurface Scale"].default_value = 0.02
    if coat:
        bsdf.inputs["Coat Weight"].default_value = coat
        bsdf.inputs["Coat Roughness"].default_value = 0.08
    if emission is not None:
        bsdf.inputs["Emission Color"].default_value = (*emission, 1.0)
        bsdf.inputs["Emission Strength"].default_value = strength
    _MATS[name] = mat
    return mat


def finish(ob, mat, bevel=0.010, segments=3, smooth=True, angle=38.0, weighted=False):
    """Assign material, round the hard edges, and keep the flats flat."""
    if mat is not None:
        ob.data.materials.append(mat)
    if smooth:
        for poly in ob.data.polygons:
            poly.use_smooth = True
    if bevel:
        mod = ob.modifiers.new("bevel", "BEVEL")
        mod.width = bevel
        mod.segments = segments
        mod.limit_method = "WEIGHT" if weighted else "ANGLE"
        mod.angle_limit = radians(angle)
        mod.miter_outer = "MITER_ARC"
    if smooth:
        wn = ob.modifiers.new("normals", "WEIGHTED_NORMAL")
        wn.mode = "FACE_AREA"
        wn.weight = 100
        wn.keep_sharp = False
    return ob


def signed_area(pts):
    n = len(pts)
    return 0.5 * sum(pts[i][0] * pts[(i + 1) % n][1] - pts[(i + 1) % n][0] * pts[i][1] for i in range(n))


def inset(pts, delta):
    """Shrink a polygon by `delta` on every side (mitred), leaving a seam gap."""
    pts = [Vector(p[:2]) for p in pts]
    if signed_area(pts) < 0:
        pts.reverse()
        flipped = True
    else:
        flipped = False
    n = len(pts)
    out = []
    for i in range(n):
        p, a, b = pts[i], pts[i - 1], pts[(i + 1) % n]
        e1 = (p - a).normalized()
        e2 = (b - p).normalized()
        n1 = Vector((-e1.y, e1.x))
        n2 = Vector((-e2.y, e2.x))
        denom = 1.0 + n1.dot(n2)
        if denom < 1e-4:
            out.append(tuple(p + n1 * delta))
        else:
            out.append(tuple(p + (n1 + n2) * (delta / denom)))
    if flipped:
        out.reverse()
    return out


def fillet(pts, radius, steps=6):
    """Round the corners of a polygon. `radius` is a number or a per-vertex list."""
    out = []
    n = len(pts)
    for i in range(n):
        r = radius[i] if isinstance(radius, (list, tuple)) else radius
        p = Vector(pts[i][:2])
        if not r:
            out.append(tuple(pts[i]))
            continue
        a = Vector(pts[i - 1][:2])
        b = Vector(pts[(i + 1) % n][:2])
        u = (a - p).normalized()
        v = (b - p).normalized()
        ang = u.angle(v)
        if ang < 1e-3 or abs(ang - math.pi) < 1e-3:
            out.append(tuple(pts[i]))
            continue
        t = min(r / math.tan(ang / 2), (a - p).length * 0.45, (b - p).length * 0.45)
        rr = t * math.tan(ang / 2)
        centre = p + (u + v).normalized() * (rr / math.sin(ang / 2))
        start = p + u * t
        end = p + v * t
        a0 = atan2(start.y - centre.y, start.x - centre.x)
        a1 = atan2(end.y - centre.y, end.x - centre.x)
        da = a1 - a0
        while da > math.pi:
            da -= 2 * math.pi
        while da < -math.pi:
            da += 2 * math.pi
        for k in range(steps + 1):
            ang_k = a0 + da * k / steps
            out.append((centre.x + rr * cos(ang_k), centre.y + rr * sin(ang_k)))
    return out


def prism(name, pts, z0, z1, to3d=None, ztop=None):
    """Extrude a 2D outline. `ztop` optionally gives a height per vertex (ramps)."""
    pts = [tuple(p) for p in pts]
    if ztop is not None:
        ztop = list(ztop)
    if signed_area(pts) < 0:
        pts.reverse()
        if ztop is not None:
            ztop.reverse()
    to3d = to3d or (lambda a, b, t: (a, b, t))
    bm = bmesh.new()
    bot = [bm.verts.new(to3d(a, b, z0)) for a, b in pts]
    top = [bm.verts.new(to3d(a, b, ztop[i] if ztop is not None else z1)) for i, (a, b) in enumerate(pts)]
    bm.faces.new(top)
    bm.faces.new(list(reversed(bot)))
    n = len(pts)
    for i in range(n):
        j = (i + 1) % n
        bm.faces.new((bot[i], bot[j], top[j], top[i]))
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
    mesh = bpy.data.meshes.new(name)
    bm.to_mesh(mesh)
    bm.free()
    return bpy.data.objects.new(name, mesh)


def cylinder_x(name, radius, x0, x1, centre_y, centre_z, segments=144, weights=None):
    """Cylinder along X. `weights` = (weight at x0 rim, weight at x1 rim) for the bevel."""
    bm = bmesh.new()
    bmesh.ops.create_cone(bm, cap_ends=True, cap_tris=False, segments=segments, radius1=radius, radius2=radius, depth=abs(x1 - x0))
    bmesh.ops.rotate(bm, verts=bm.verts[:], cent=(0, 0, 0), matrix=Matrix.Rotation(radians(90), 3, "Y"))
    bmesh.ops.translate(bm, verts=bm.verts[:], vec=((x0 + x1) / 2, centre_y, centre_z))
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
    if weights is not None:
        layer = bm.edges.layers.float.new("bevel_weight_edge")
        mid = (x0 + x1) / 2
        lo, hi = (weights if x0 < x1 else weights[::-1])
        for edge in bm.edges:
            xa, xb = edge.verts[0].co.x, edge.verts[1].co.x
            if abs(xa - xb) < 1e-6:  # rim edge
                edge[layer] = lo if xa < mid else hi
    mesh = bpy.data.meshes.new(name)
    bm.to_mesh(mesh)
    bm.free()
    return bpy.data.objects.new(name, mesh)


def box(name, x0, x1, y0, y1, z0, z1):
    return prism(name, [(x0, y0), (x1, y0), (x1, y1), (x0, y1)], z0, z1)


def flat_mesh(name, polys, z, mat):
    """Thin printed marks built from polygons (each a list of xy points)."""
    bm = bmesh.new()
    for pts in polys:
        if signed_area(pts) < 0:
            pts = list(reversed(pts))
        bm.faces.new([bm.verts.new((x, y, z)) for x, y in pts])
    mesh = bpy.data.meshes.new(name)
    bm.to_mesh(mesh)
    bm.free()
    ob = bpy.data.objects.new(name, mesh)
    ob.data.materials.append(mat)
    ob.visible_shadow = False
    return ob


def arc_band(cx, cy, r, a0, a1, w, steps=14):
    outer = [(cx + (r + w / 2) * cos(a0 + (a1 - a0) * k / steps), cy + (r + w / 2) * sin(a0 + (a1 - a0) * k / steps)) for k in range(steps + 1)]
    inner = [(cx + (r - w / 2) * cos(a0 + (a1 - a0) * k / steps), cy + (r - w / 2) * sin(a0 + (a1 - a0) * k / steps)) for k in range(steps + 1)]
    return outer + inner[::-1]


_FONT_CACHE = {}
_CAP = {}


def font(key):
    path = FONTS[key]
    if path not in _FONT_CACHE:
        _FONT_CACHE[path] = bpy.data.fonts.load(path)
    return _FONT_CACHE[path]


def cap_ratio(key):
    """Cap height per unit of Blender text size, measured from the glyphs themselves."""
    if key not in _CAP:
        curve = bpy.data.curves.new("probe", "FONT")
        curve.body = "H"
        curve.font = font(key)
        curve.size = 1.0
        ob = bpy.data.objects.new("probe", curve)
        link(ob)
        bpy.context.view_layer.update()
        mesh = ob.to_mesh()
        ys = [v.co.y for v in mesh.vertices]
        _CAP[key] = max(ys) - min(ys)
        ob.to_mesh_clear()
        bpy.data.objects.remove(ob)
    return _CAP[key]


def text(name, body, cap, loc, mat, face="regular", spacing=1.0, rot_z=0.0, stretch=1.0, align="CENTER", parent=None, lift=0.0012, weight=0.0):
    """Flat printed legend. `loc` is the centre of the cap height."""
    curve = bpy.data.curves.new(name, "FONT")
    curve.body = body
    curve.font = font(face)
    curve.size = cap / cap_ratio(face)
    curve.align_x = align
    curve.align_y = "BOTTOM_BASELINE"
    curve.space_character = spacing
    curve.offset = weight
    curve.materials.append(mat)
    ob = bpy.data.objects.new(name, curve)
    holder = empty(name + "_at", (loc[0], loc[1], loc[2] + lift), parent)
    holder.rotation_euler = (0, 0, rot_z)
    link(ob, holder)
    ob.location = (0, -cap / 2, 0)
    ob.scale = (stretch, 1, 1)
    ob.visible_shadow = False
    return holder


# ---- materials -----------------------------------------------------------------
def mats(kind):
    return {
        "body": material("body", (0.715, 0.716, 0.712), rough=0.46, sss=0.10),
        "handle": material("handle", (0.722, 0.723, 0.719), rough=0.38, sss=0.12),
        "dark": material("dark", (0.010, 0.010, 0.010), rough=0.7),
        "lens": material("lens", (0.004, 0.004, 0.005), rough=0.10, coat=0.7),
        "ink": material("ink_" + kind, (0.062, 0.062, 0.066) if kind == "smart" else (0.33, 0.33, 0.33), rough=0.6, spec=0.2),
        "steel": material("steel", (0.800, 0.803, 0.800), rough=0.38, coat=0.12),
    }


# ---- breaker -------------------------------------------------------------------
def rot_about_pivot(u, z, phi):
    """Rotate a handle point (u along the breaker, z height) about the pivot."""
    zz = z - PIVOT_Z
    return (u * cos(phi) + zz * sin(phi), -u * sin(phi) + zz * cos(phi) + PIVOT_Z)


def build_handle(root, cx, state, m, plain=False):
    """The rocker: a barrel with a finger lip at each end. Built at centre, then tilted."""
    py = fy(PIVOT_D)
    pivot = empty("pivot", (cx, py, PIVOT_Z), root)
    top = PIVOT_Z + BARREL_R

    def to3d(u, z, t):  # handle profile plane -> breaker space
        return (cx + t, py - u, z)

    barrel = cylinder_x("barrel", BARREL_R, cx - LIP_X, cx + LIP_X, py, PIVOT_Z)
    # Indicator window: a shallow frame with a slot through to the coloured flag.
    frame = box("win_frame", cx - 0.224, cx + 0.224, py - 0.050, py + 0.052, top - 0.040, top + 0.2)
    slot = box("win_slot", cx - 0.209, cx + 0.209, py - 0.040, py + 0.012, top - 0.20, top + 0.2)
    for cutter in () if plain else (frame, slot):
        link(cutter, pivot)
        cutter.matrix_parent_inverse = Matrix.Translation(-pivot.location)
        cutter.hide_render = True
        cutter.display_type = "WIRE"
        cut = barrel.modifiers.new("cut", "BOOLEAN")
        cut.operation = "DIFFERENCE"
        cut.solver = "EXACT"
        cut.object = cutter
    finish(barrel, m["handle"], bevel=0.007, segments=2)
    parts = [barrel]

    if not plain:
        flag = box("flag", cx - 0.190, cx + 0.209, py - 0.040, py + 0.012, top - 0.16, top - 0.062)
        glow = 0.0 if state == "off" else 0.45
        flag.data.materials.append(material("flag_" + state, FLAG[state], rough=0.45, emission=FLAG[state], strength=glow))
        parts.append(flag)
        well = box("win_dark", cx - 0.209, cx + 0.209, py - 0.040, py + 0.012, top - 0.20, top - 0.090)
        well.data.materials.append(m["dark"])
        parts.append(well)

    # Each lip is drawn where it rests when tucked down, then swung back to centre.
    tip_u = (CAV_D1 - PIVOT_D) - 0.006
    tip_z = 0.066
    rise = tan(radians(3.5))  # tucked face still climbs slightly toward the barrel
    lean = radians(6.0)
    for side, legend in ((1, "ON"), (-1, "OFF")):
        tucked = [
            (tip_u, tip_z),
            (0.16, tip_z + (tip_u - 0.16) * rise),
            (0.16, tip_z - 0.42),
            (tip_u + 0.42 * sin(lean), tip_z - 0.42 * cos(lean)),
        ]
        phi = -ALPHA  # tucked -> centre
        profile = [rot_about_pivot(u, z, phi) for u, z in tucked]
        profile = [(side * u, z) for u, z in profile]
        lip = prism("lip_" + legend, fillet(profile, [0.030, 0, 0, 0], steps=6), -LIP_X, LIP_X, to3d=to3d)
        finish(lip, m["handle"], bevel=0.014, segments=3)
        parts.append(lip)
        # Legend sits on the lip's top face.
        lu = tip_u - 0.105
        cu, cz = rot_about_pivot(lu, tip_z + (tip_u - lu) * rise, phi)
        if not plain:
            holder = text("legend_" + legend, legend, 0.081, (cx, py - side * cu, cz), m["ink"])
            holder.rotation_euler = (side * (phi + radians(3.5)), 0, 0)
            parts.append(holder)

    for part in parts:
        if part.name not in bpy.context.scene.collection.objects:
            link(part)
        part.parent = pivot
        part.matrix_parent_inverse = Matrix.Translation(-pivot.location)
    pivot.rotation_euler = (HANDLE_ANGLE[state], 0, 0)
    return pivot


def build_pole_face(root, cx, kind, m, left_edge=None, lower_left=True, guards=True, plain=False):
    """The raised face of the pole that carries the handle, as its two moulded halves."""
    hw = FACE_W / 2
    xl = cx - hw if left_edge is None else left_edge
    xr = cx + hw
    c0, c1 = cx - CAV_X, cx + CAV_X
    z0 = -FACE_H - 0.03
    crease_l, crease_r = 0.264, 0.315
    chin_side, chin_mid = 1.521, 1.537
    jog0, jog1, jx = 2.030, 2.052, cx - 0.066
    led0, led1 = 2.652, 2.716
    r = 0.030

    def P(pts):
        return [(x, fy(d)) for x, d in pts]

    def shell(name, pts, radii):
        pts2 = inset(P(pts), SEAM)
        pts2 = fillet(pts2, radii)
        ob = prism(name, pts2, z0, 0.0)
        finish(ob, m["body"], bevel=0.008)
        link(ob, root)

    if kind == "smart":
        seam_r = [(cx, FACE_L), (cx, led0), (jx, led0), (jx, jog1), (cx, jog0)]
        seam_l = [(cx, jog0), (jx, jog1), (jx, led1), (cx, led1), (cx, FACE_L)]
    else:
        seam_r = [(cx, FACE_L), (cx, 2.795), (jx, 2.777), (jx, jog1), (cx, jog0)]
        seam_l = [(cx, jog0), (jx, jog1), (jx, 2.777), (cx, 2.795), (cx, FACE_L)]

    right = [(c0, 0), (xr, 0), (xr, FACE_L)] + seam_r + [(cx, chin_mid), (c1, chin_side), (c1, crease_r), (c0, crease_l)]
    shell("half_r", right, [0, r, r] + [0] * (len(right) - 3))
    if lower_left:
        left = [(xl, 0), (c0, 0), (c0, chin_side), (cx, chin_mid)] + seam_l + [(xl, FACE_L)]
        shell("half_l", left, [r if left_edge is None else 0] + [0] * (len(left) - 2) + [r if left_edge is None else 0])

    # Landing ramps under each lip (part of the same mouldings, so no seam).
    ramps = {
        "ramp_top": ([(c0 + SEAM, crease_l - 0.006), (c1 - SEAM, crease_r - 0.006), (c1 - SEAM, CAV_D0), (c0 + SEAM, CAV_D0)], [-0.001, -0.001, -0.030, -0.030]),
        "chin_r": ([(cx + SEAM, CAV_D1), (c1 - SEAM, CAV_D1), (c1 - SEAM, chin_side + 0.006), (cx + SEAM, chin_mid + 0.006)], [-0.030, -0.030, -0.001, -0.001]),
        "chin_l": ([(c0 + SEAM, CAV_D1), (cx - SEAM, CAV_D1), (cx - SEAM, chin_mid + 0.006), (c0 + SEAM, chin_side + 0.006)], [-0.030, -0.030, -0.001, -0.001]),
    }
    for name, (pts, zt) in ramps.items():
        ob = prism(name, P(pts), z0, 0.0, ztop=zt)
        finish(ob, m["body"], bevel=0.003, segments=2)
        link(ob, root)

    # Fixed guards either side of the rocker.
    py = fy(PIVOT_D)
    for side in (-1, 1) if guards else ():
        ear = cylinder_x("ear", BARREL_R, cx + side * (CAV_X + 0.001), cx + side * EAR_X, py, PIVOT_Z, weights=(0.16, 1.0))
        finish(ear, m["body"], bevel=0.062, segments=6, weighted=True)
        link(ear, root)

    # Dark mechanism below the opening.
    if not plain:
        liner = box("cavity", c0 - 0.02, c1 + 0.02, fy(CAV_D1) - 0.02, fy(CAV_D0) + 0.02, -0.9, -0.075)
        liner.data.materials.append(m["dark"])
        link(liner, root)

    if kind == "smart" and not plain:
        lens = box("led", jx + 0.004, cx - 0.004, fy(led1) + 0.004, fy(led0) - 0.004, z0, -0.006)
        lens.data.materials.append(m["lens"])
        link(lens, root)


def build_legends(root, cx, kind, m, rating=None):
    ink = m["ink"]
    if BRAND:
        # Wordmark, approximated in a plain heavy grotesque, with its square frame.
        text("logo", "LEVITON", 0.080, (cx + 0.004, fy(0.192), 0), ink, face="bold", spacing=1.03, stretch=1.11, parent=root, weight=0.0022)
        sq0, sq1, st, w = cx + 0.112, cx + 0.288, 0.040, 0.006
        frame = [
            [(sq0, fy(st)), (sq1, fy(st)), (sq1, fy(st + w)), (sq0, fy(st + w))],
            [(sq0, fy(st)), (sq0 + w, fy(st)), (sq0 + w, fy(0.146)), (sq0, fy(0.146))],
            [(sq1 - w, fy(st)), (sq1, fy(st)), (sq1, fy(0.232)), (sq1 - w, fy(0.232))],
        ]
        link(flat_mesh("logo_frame", frame, 0.0012, ink), root)
    if rating:
        text("rating", str(rating), 0.076, (cx + 0.19, fy(1.775), 0), ink, parent=root)
    if kind == "smart":
        text("remote1", "REMOTELY", 0.036, (cx + 0.192, fy(1.915), 0), ink, parent=root)
        text("remote2", "OPERATED", 0.036, (cx + 0.192, fy(1.972), 0), ink, parent=root)
        text("led_off", "OFF", 0.084, (cx + 0.156, fy(2.688), 0), ink, face="narrow", spacing=1.0, parent=root)
        text("type", "T", 0.076, (cx + 0.030, fy(2.808), 0), ink, face="narrow", parent=root)
        # Radio mark: a dot with two arcs each side.
        ix, iy = cx + 0.282, fy(2.805)
        marks = [[(ix + 0.009 * cos(a * math.pi / 8), iy + 0.009 * sin(a * math.pi / 8)) for a in range(16)]]
        for rad in (0.029, 0.050):
            marks.append(arc_band(ix, iy, rad, radians(-52), radians(52), 0.0065))
            marks.append(arc_band(ix, iy, rad, radians(128), radians(232), 0.0065))
        link(flat_mesh("rf", marks, 0.0012, ink), root)
    else:
        text("type", "T", 0.080, (cx + 0.19, fy(2.731), 0), ink, parent=root)


def build_breaker(poles=1, kind="smart", state="on", rating=None, name="breaker", bare=False, legends=True, proxy=False):
    """Returns the root empty. The handle pole is the right-hand pole of a 2-pole unit."""
    m = mats(kind)
    root = empty(name)
    width = BODY_W + (poles - 1) * PITCH
    cx = (poles - 1) * PITCH / 2  # centre of the handle pole
    x_left = -width / 2
    z0 = -FACE_H - 0.03
    c0 = cx - CAV_X

    def P(pts):
        return [(x, fy(d)) for x, d in pts]

    if poles == 1:
        build_pole_face(root, cx, kind, m, guards=not bare, plain=proxy)
    else:
        # Blank pole to the left: moulded panels, as on the 2-pole catalog photo.
        fl = x_left + (BODY_W - FACE_W) / 2
        seam_a, seam_a2 = x_left + 0.466, x_left + 0.420
        boundary = cx - 0.5  # line between the two poles
        split_d, jog_d = 1.839, 2.040
        jx = cx - 0.066
        r = 0.030
        led_bottom = 2.716 if kind == "smart" else None
        if kind == "smart":
            d_seam = [(cx, 2.030), (jx, 2.052), (jx, led_bottom), (cx, led_bottom), (cx, FACE_L)]
        else:
            d_seam = [(cx, 2.030), (jx, 2.052), (jx, 2.777), (cx, 2.795), (cx, FACE_L)]
        panels = {
            "panel_a": ([(fl, 0), (seam_a, 0), (seam_a, jog_d), (seam_a2, jog_d + 0.02), (seam_a2, FACE_L), (fl, FACE_L)], [r, 0, 0, 0, 0, r]),
            "panel_b": ([(seam_a, 0), (boundary, 0), (boundary, split_d), (seam_a, split_d)], 0),
            "rail_l": ([(boundary, 0), (c0, 0), (c0, 1.521), (cx, 1.537), (cx, split_d), (boundary, split_d)], 0),
            "panel_d": ([(seam_a, split_d), (cx, split_d)] + d_seam + [(seam_a2, FACE_L), (seam_a2, jog_d + 0.02), (seam_a, jog_d)], 0),
        }
        for pname, (pts, radii) in panels.items():
            pts2 = inset(P(pts), SEAM)
            if radii:
                pts2 = fillet(pts2, radii)
            ob = prism(pname, pts2, z0, 0.0)
            finish(ob, m["body"], bevel=0.008)
            link(ob, root)
        build_pole_face(root, cx, kind, m, left_edge=boundary, lower_left=False, guards=not bare, plain=proxy)

    # Housing below the raised face; the shelves at each end show in the product shot.
    top, bot = -STEP_TOP, FACE_L + STEP_BOT
    xr = x_left + width
    low = -0.062  # the shelf at the terminal end sits closer to the face
    side = [(top, -1.6), (top, -FACE_H - 0.10), (top + 0.085, -FACE_H), (FACE_L - 0.012, -FACE_H), (FACE_L - 0.012, low), (bot - 0.02, low), (bot, low - 0.02), (bot, -1.6)]
    body = prism("body", side, x_left, xr, to3d=lambda d, z, t: (t, fy(d), z))
    finish(body, m["body"], bevel=0.022, segments=4)
    link(body, root)
    if not proxy:
        # Hairline seams across the shelves.
        groove_mat = material("groove", (0.10, 0.10, 0.10), rough=0.8)
        edge = 0.095
        seams = [[(cx, top + edge), (cx, -0.115), (c0, -0.064), (c0, 0.0)], [(cx, FACE_L), (cx, bot - edge)]]
        if poles == 2:
            for sx in (x_left + 0.477, cx - 0.5):
                seams += [[(sx, top + edge), (sx, 0.0)], [(sx, FACE_L), (sx, bot - edge)]]
        quads = []
        for path in seams:
            for (xa, da), (xb, db) in zip(path, path[1:]):
                a, b2 = Vector((xa, fy(da))), Vector((xb, fy(db)))
                n = (b2 - a).normalized()
                t = Vector((-n.y, n.x)) * SEAM
                quads.append([tuple(a + t - n * SEAM), tuple(b2 + t + n * SEAM), tuple(b2 - t + n * SEAM), tuple(a - t - n * SEAM)])
        for part, zq in ((quads[:3], -FACE_H + 0.0008), (quads[3:], low + 0.0008)):
            if part:
                link(flat_mesh("shelf_seams", part, zq, groove_mat), root)

    if legends and not bare and not proxy:
        build_legends(root, cx, kind, m, rating)
    if not bare:
        build_handle(root, cx, state, m, plain=proxy)
    return root


# ---- enclosure -----------------------------------------------------------------
DF_Z = -0.02  # dead front surface; breaker faces stand 0.02 proud of it
SLOT_PAD = 0.035  # clearance at each end of a breaker in its opening
SLOT_END = 0.012  # opening beyond the first and last space
OPEN_L = FACE_L + 2 * SLOT_PAD
CENTER_W = 0.80  # dead front strip between the two columns
TILE_M = 0.10  # dead front included at each end of a breaker tile
FIELD_M = 0.18  # dead front outside each column, up to the raised rim
# Frame profile, measured inward from the flat cover (see build_frame).
RAMP_W, PLATEAU_W, LIP_W, GUTTER_W, RIM_W = 0.22, 0.26, 0.03, 0.12, 0.05
BOSS_H, RECESS, RIM_H = 0.09, 0.27, 0.03
FRAME_W = RAMP_W + PLATEAU_W + LIP_W + GUTTER_W + RIM_W
COVER_Z = DF_Z + RECESS - BOSS_H
CHAMFER = 0.22


def descendants(root):
    out = []
    for child in root.children:
        out.append(child)
        out.extend(descendants(child))
    return out


def place(root, column, y):
    """Seat an upright breaker in the left (-1) or right (+1) column, logo toward the centre."""
    x = CENTER_W / 2 + SLOT_PAD + FACE_L / 2
    root.location = (column * x, y, 0.0)
    root.rotation_euler = (0.0, 0.0, radians(90.0) * column)
    return root


def slot_x(column):
    """Inner and outer x of a column's opening."""
    return column * CENTER_W / 2, column * (CENTER_W / 2 + OPEN_L)


def rrect(hw, hh, r, n=14, cx=0.0, cy=0.0):
    """Rounded rectangle outline, counter-clockwise, with a fixed vertex count."""
    r = max(min(r, hw - 1e-4, hh - 1e-4), 1e-4)
    pts = []
    for (sx, sy, a0) in ((1, 1, 0.0), (-1, 1, 90.0), (-1, -1, 180.0), (1, -1, 270.0)):
        ox, oy = cx + sx * (hw - r), cy + sy * (hh - r)
        for k in range(n + 1):
            a = radians(a0 + 90.0 * k / n)
            pts.append((ox + r * cos(a), oy + r * sin(a)))
    return pts


def loft(name, loops, cap=None):
    """Skin a stack of same-count outlines; `loops` = [(outline, z), ...] from outside in."""
    bm = bmesh.new()
    rings = [[bm.verts.new((x, y, z)) for x, y in outline] for outline, z in loops]
    n = len(rings[0])
    for a, b in zip(rings, rings[1:]):
        for i in range(n):
            j = (i + 1) % n
            bm.faces.new((a[i], a[j], b[j], b[i]))
    if cap:
        bm.faces.new(rings[-1])
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
    for face in bm.faces:
        face.smooth = True
    mesh = bpy.data.meshes.new(name)
    bm.to_mesh(mesh)
    bm.free()
    return bpy.data.objects.new(name, mesh)


def build_dead_front(m, slots, hw=14.0, hh=14.0, radius=0.0, cx=0.0, cy=0.0, rounded=0.03):
    """Flat dead front with openings. `slots` = [(x0, x1, y0, y1), ...]."""
    outline = rrect(hw, hh, radius, n=18, cx=cx, cy=cy) if radius else [(cx - hw, cy - hh), (cx + hw, cy - hh), (cx + hw, cy + hh), (cx - hw, cy + hh)]
    plate = prism("dead_front", outline, DF_Z - 0.08, DF_Z)
    for i, (x0, x1, y0, y1) in enumerate(slots):
        xa, xb = min(x0, x1), max(x0, x1)
        cutter = prism("slot%d" % i, fillet([(xa, y0), (xb, y0), (xb, y1), (xa, y1)], rounded), DF_Z - 0.3, DF_Z + 0.3)
        link(cutter)
        cutter.hide_render = True
        cut = plate.modifiers.new("slot", "BOOLEAN")
        cut.operation = "DIFFERENCE"
        cut.solver = "EXACT"
        cut.object = cutter
    finish(plate, m["steel"], bevel=0.012, segments=3)
    link(plate)
    floor = prism("interior", [(cx - hw - 3, cy - hh - 3), (cx + hw + 3, cy - hh - 3), (cx + hw + 3, cy + hh + 3), (cx - hw - 3, cy + hh + 3)], -1.4, -1.3)
    floor.data.materials.append(m["dark"])
    link(floor)
    return plate


def build_filler(m, column, y, rows=1):
    """Blank plate that fills an unused space."""
    x0, x1 = slot_x(column)
    xa, xb = min(x0, x1) + 0.010, max(x0, x1) - 0.010
    h = rows * PITCH / 2 - 0.007
    plate = prism("filler", fillet([(xa, y - h), (xb, y - h), (xb, y + h), (xa, y + h)], 0.025), DF_Z - 0.2, DF_Z + 0.012)
    finish(plate, m["steel"], bevel=0.018, segments=4)
    link(plate)
    return plate


# Frame profile from the dead front field outward: (distance, height, corner radius).
_WALL = RIM_W + GUTTER_W
_LIP = _WALL + LIP_W
_PLAT = _LIP + PLATEAU_W
FRAME_PROFILE = [
    (0.000, DF_Z, 0.50),
    (0.012, DF_Z, 0.495),
    (RIM_W - 0.010, DF_Z - RIM_H, 0.47),
    (RIM_W, DF_Z - RIM_H, 0.46),
    (_WALL - 0.006, DF_Z - RIM_H, 0.31),
    (_WALL, DF_Z - RIM_H, 0.30),
    (_WALL, DF_Z - RIM_H + 0.012, 0.30),
    (_WALL, DF_Z + RECESS - 0.016, 0.30),
    (_WALL + 0.006, DF_Z + RECESS - 0.004, 0.306),
    (_LIP, DF_Z + RECESS, 0.32),
    (_LIP + 0.02, DF_Z + RECESS, 0.34),
    (_PLAT - 0.03, DF_Z + RECESS, 0.56),
    (_PLAT + 0.02, DF_Z + RECESS - 0.006, 0.63),
    (FRAME_W - 0.06, COVER_Z + 0.014, 0.86),
    (FRAME_W - 0.015, COVER_Z + 0.003, 0.93),
    (FRAME_W + 0.03, COVER_Z, 1.00),
    (FRAME_W + 0.05, COVER_Z, 1.02),
    (FRAME_W + 0.10, COVER_Z, 1.07),
]
FRAME_OUT = FRAME_W + 0.10  # where the frame is flat cover again


def build_frame(m, hw, hh, cx=0.0, cy=0.0, cover=None, extent=20.0, cap=False):
    """Cover with its embossed door surround, the door opening, and the dead front's raised rim.

    `hw`, `hh` are the half size of the flat dead front field inside the rim. `cover` =
    (half width, half height, centre y) adds the cover's chamfered outer edge.
    """
    loops = []
    if cover:
        cw, ch, ccy = cover
        loops.append((rrect(cw, ch, 0.05, n=18, cx=cx, cy=ccy), COVER_Z - 0.20))
        loops.append((rrect(cw - CHAMFER, ch - CHAMFER, 0.03, n=18, cx=cx, cy=ccy), COVER_Z))
        loops.append((rrect(cw - CHAMFER - 0.02, ch - CHAMFER - 0.02, 0.03, n=18, cx=cx, cy=ccy), COVER_Z))
    else:
        loops.append((rrect(extent, extent, 0.03, n=18, cx=cx, cy=cy), COVER_Z))
    for grow, z, radius in reversed(FRAME_PROFILE):
        loops.append((rrect(hw + grow, hh + grow, radius, n=18, cx=cx, cy=cy), z))
    frame = loft("frame", loops, cap=cap)
    finish(frame, m["steel"], bevel=0)
    link(frame)
    return frame


def build_screw(m, x, y, angle=20.0, z=None):
    """Painted round-head slotted screw."""
    z = COVER_Z if z is None else z
    bm = bmesh.new()
    rad, height, rings, segs = 0.185, 0.068, 10, 48
    sphere_r = (rad * rad + height * height) / (2 * height)
    verts = [[bm.verts.new((0, 0, height))]]
    amax = math.asin(rad / sphere_r)
    for i in range(1, rings + 1):
        a = amax * i / rings
        ring = [bm.verts.new((sphere_r * sin(a) * cos(2 * math.pi * k / segs), sphere_r * sin(a) * sin(2 * math.pi * k / segs), height - sphere_r * (1 - cos(a)))) for k in range(segs)]
        verts.append(ring)
    for k in range(segs):
        bm.faces.new((verts[0][0], verts[1][k], verts[1][(k + 1) % segs]))
    for i in range(1, rings):
        for k in range(segs):
            bm.faces.new((verts[i][k], verts[i + 1][k], verts[i + 1][(k + 1) % segs], verts[i][(k + 1) % segs]))
    bm.faces.new(list(reversed(verts[-1])))
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
    for face in bm.faces:
        face.smooth = True
    mesh = bpy.data.meshes.new("screw")
    bm.to_mesh(mesh)
    bm.free()
    head = bpy.data.objects.new("screw", mesh)
    cutter = box("screw_slot", -0.3, 0.3, -0.019, 0.019, height - 0.036, height + 0.2)
    link(cutter, head)
    cutter.hide_render = True
    cut = head.modifiers.new("slot", "BOOLEAN")
    cut.operation = "DIFFERENCE"
    cut.solver = "EXACT"
    cut.object = cutter
    head.data.materials.append(material("screw", (0.80, 0.803, 0.80), rough=0.30, coat=0.2))
    bev = head.modifiers.new("bevel", "BEVEL")
    bev.width = 0.006
    bev.segments = 2
    bev.limit_method = "ANGLE"
    bev.angle_limit = radians(50)
    link(head)
    head.location = (x, y, z)
    head.rotation_euler = (0, 0, radians(angle))
    return head


def text_flat(name, body, cap, x, y, z, mat, face="regular", align="CENTER", rot=0.0, spacing=1.0):
    return text(name, body, cap, (x, y, z), mat, face=face, align=align, rot_z=rot, spacing=spacing)


# ---- lighting and camera -------------------------------------------------------
def lighting(sun=2.46, dome=(0.18, 0.86), direction=(-0.10, 0.74, 0.66), softness=30.0, span=(-0.6, 0.8)):
    """Key light from above the panel plus a dome that is bright overhead and dim below."""
    scene = bpy.context.scene
    world = bpy.data.worlds.new("world")
    world.use_nodes = True
    nt = world.node_tree
    bg = nt.nodes["Background"]
    bg.inputs["Color"].default_value = (1.0, 1.0, 1.0, 1.0)
    coord = nt.nodes.new("ShaderNodeTexCoord")
    sep = nt.nodes.new("ShaderNodeSeparateXYZ")
    ramp = nt.nodes.new("ShaderNodeMapRange")
    ramp.interpolation_type = "SMOOTHSTEP"
    ramp.inputs["From Min"].default_value = span[0]
    ramp.inputs["From Max"].default_value = span[1]
    ramp.inputs["To Min"].default_value = dome[0]
    ramp.inputs["To Max"].default_value = dome[1]
    nt.links.new(coord.outputs["Generated"], sep.inputs["Vector"])
    nt.links.new(sep.outputs["Y"], ramp.inputs["Value"])
    nt.links.new(ramp.outputs["Result"], bg.inputs["Strength"])
    scene.world = world
    light = bpy.data.lights.new("key", "SUN")
    light.energy = sun
    light.angle = radians(softness)
    ob = bpy.data.objects.new("key", light)
    ob.rotation_euler = Vector(direction).normalized().to_track_quat("Z", "Y").to_euler()
    link(ob)


def camera(x0, x1, y0, y1, ppi):
    scene = bpy.context.scene
    cam = bpy.data.cameras.new("cam")
    cam.type = "ORTHO"
    w, h = x1 - x0, y1 - y0
    cam.ortho_scale = max(w, h)
    cam.clip_start = 0.1
    cam.clip_end = 100
    ob = bpy.data.objects.new("cam", cam)
    ob.location = ((x0 + x1) / 2, (y0 + y1) / 2, 20)
    link(ob)
    scene.camera = ob
    scene.render.resolution_x = round(w * ppi)
    scene.render.resolution_y = round(h * ppi)
    scene.render.resolution_percentage = 100
    return ob


def render(path, samples=200, transparent=True):
    scene = bpy.context.scene
    scene.cycles.samples = samples
    scene.render.film_transparent = transparent
    scene.render.filepath = path
    bpy.ops.render.render(write_still=True)


# ---- jobs ----------------------------------------------------------------------
MAIN_SCALE = 1.25
MAIN_W, MAIN_H, MAIN_M = 3.30, 2.40, 0.15


def job_main(job):
    """Main breaker seen through its opening at the top of the dead front."""
    reset_scene()
    m = mats("std")
    build_dead_front(m, [(-MAIN_W / 2, MAIN_W / 2, -MAIN_H / 2, MAIN_H / 2)], rounded=0.10)
    root = build_breaker(poles=2, kind="std", state=job.get("state", "on"))
    root.scale = (MAIN_SCALE, MAIN_SCALE, MAIN_SCALE)
    root.rotation_euler = (0.0, 0.0, radians(-90.0))
    root.location = (0.0, 0.0, -0.115)
    lighting(**job.get("light", {}))
    camera(-MAIN_W / 2 - MAIN_M, MAIN_W / 2 + MAIN_M, -MAIN_H / 2 - MAIN_M, MAIN_H / 2 + MAIN_M, job.get("ppi", 200))
    render(job["out"], samples=job.get("samples", 128), transparent=False)


def job_hero(job):
    reset_scene()
    poles = job.get("poles", 1)
    build_breaker(poles=poles, kind=job.get("kind", "smart"), state=job.get("state", "off"), rating=job.get("rating"))
    lighting(**job.get("light", {}))
    width = BODY_W + (poles - 1) * PITCH
    pad = job.get("pad", 0.08)
    camera(-width / 2 - pad, width / 2 + pad, fy(FACE_L + STEP_BOT) - pad, fy(-STEP_TOP) + pad, job.get("ppi", 340))
    render(job["out"], samples=job.get("samples", 200))


FIELD_Y = 0.45  # dead front above and below the columns
CAP_H = 0.20  # dead front included in the tiles that close each column


def job_preview(job):
    """A complete small panel in one render: the reference the tiled card must match."""
    reset_scene()
    layout = job["layout"]  # rows from the top: [left, right] each None | "skip" | {poles, kind, state}
    rows = len(layout)
    m = mats("smart")
    y_top = rows * PITCH / 2
    hw = CENTER_W / 2 + OPEN_L + FIELD_M
    hh = y_top + FIELD_Y
    slots = []
    for column in (-1, 1):
        x0, x1 = slot_x(column)
        slots.append((x0, x1, -y_top - SLOT_END, y_top + SLOT_END))
    build_dead_front(m, slots, hw + 0.008, hh + 0.008, radius=0.505)
    for column, idx in ((-1, 0), (1, 1)):
        r = 0
        while r < rows:
            cell = layout[r][idx]
            if cell is None:
                build_filler(m, column, y_top - (r + 0.5) * PITCH)
                r += 1
                continue
            if cell == "skip":
                r += 1
                continue
            poles = cell.get("poles", 1)
            root = build_breaker(poles=poles, kind=cell.get("kind", "smart"), state=cell.get("state", "on"), rating=cell.get("rating"))
            place(root, column, y_top - (r + poles / 2) * PITCH)
            r += poles
    cw = hw + FRAME_OUT + job.get("side", 2.0)
    ch = hh + FRAME_OUT + job.get("margin", 1.0)
    build_frame(m, hw, hh, cover=(cw, ch, 0.0))
    for sx in (-0.56, 0.56):
        for sy in (-1, 1):
            build_screw(m, sx * cw, sy * (ch - 0.55), angle=20 + 70 * (sx > 0) + 35 * (sy > 0))
    lighting(**job.get("light", {}))
    pad = 0.3
    camera(-cw - pad, cw + pad, -ch - pad, ch + pad, job.get("ppi", 110))
    render(job["out"], samples=job.get("samples", 96))


FRAME_SLICE = FRAME_OUT + 0.56  # nine-slice border: frame plus the field's rounded corner
COVER_SLICE = CHAMFER + 0.10
OVERFLOW = 0.42  # shadow a breaker casts onto the space below it


def tile_bounds(column):
    x0, x1 = slot_x(column)
    return min(x0, x1) - TILE_M, max(x0, x1) + TILE_M


def job_tile(job):
    """One space of one column, as the card stacks them."""
    reset_scene()
    column = job["column"]
    what = job["what"]
    m = mats("smart")
    x0, x1 = slot_x(column)
    xa, xb = tile_bounds(column)
    ppi = job.get("ppi", 200)
    generic = dict(poles=1, kind="smart", state="on", legends=False)
    if what == "cap_top":
        build_dead_front(m, [(x0, x1, -8.0, PITCH / 2 + SLOT_END)])
        place(build_breaker(**generic), column, 0.0)
        camera(xa, xb, PITCH / 2, PITCH / 2 + CAP_H, ppi)
    elif what == "cap_bottom":
        build_dead_front(m, [(x0, x1, -PITCH / 2 - SLOT_END, 8.0)])
        place(build_breaker(poles=1, bare=True), column, 0.0)
        camera(xa, xb, -PITCH / 2 - CAP_H, -PITCH / 2, ppi)
    else:
        poles = job.get("poles", 1)
        half = poles * PITCH / 2
        build_dead_front(m, [(x0, x1, -8.0, 8.0)])
        if what == "filler":
            build_filler(m, column, 0.0)
        else:
            place(build_breaker(poles=poles, kind=job.get("kind", "smart"), state=job.get("state", "on")), column, 0.0)
        place(build_breaker(poles=1, bare=True), column, half + PITCH / 2)
        # The space below only receives this breaker's shadow. A plain slab at
        # face height catches it, so the shadow suits whatever ends up there:
        # a breaker, the blank half of a 2-pole unit, or a filler plate.
        xs = sorted((x0, x1))
        slab = box("catcher", xs[0] + SLOT_PAD, xs[1] - SLOT_PAD, -half - PITCH + 0.045, -half - 0.045, -0.6, 0.0)
        slab.data.materials.append(m["body"])
        slab.is_shadow_catcher = True
        link(slab)
        camera(xa, xb, -half - OVERFLOW, half, ppi)
    lighting(**job.get("light", {}))
    render(job["out"], samples=job.get("samples", 128))


def job_frame(job):
    """Door surround as a nine-slice sample: flat cover outside, dead front field inside."""
    reset_scene()
    m = mats("smart")
    mid = 0.40
    half = FRAME_SLICE - FRAME_OUT + mid / 2
    build_frame(m, half, half, cap=True)
    lighting(**job.get("light", {}))
    edge = half + FRAME_OUT
    camera(-edge, edge, -edge, edge, job.get("ppi", 160))
    render(job["out"], samples=job.get("samples", 160), transparent=False)


def job_cover(job):
    """Cover plate with its chamfered edge, as a nine-slice sample."""
    reset_scene()
    m = mats("smart")
    half = COVER_SLICE + 0.20
    loops = [
        (rrect(half, half, 0.05, n=10), COVER_Z - 0.20),
        (rrect(half - CHAMFER, half - CHAMFER, 0.03, n=10), COVER_Z),
        (rrect(half - CHAMFER - 0.02, half - CHAMFER - 0.02, 0.03, n=10), COVER_Z),
    ]
    plate = loft("cover", loops, cap=True)
    finish(plate, m["steel"], bevel=0)
    link(plate)
    lighting(**job.get("light", {}))
    camera(-half, half, -half, half, job.get("ppi", 160))
    render(job["out"], samples=job.get("samples", 160))


def job_screw(job):
    reset_scene()
    m = mats("smart")
    plate = prism("cover", [(-6, -6), (6, -6), (6, 6), (-6, 6)], COVER_Z - 0.1, COVER_Z)
    plate.data.materials.append(m["steel"])
    plate.is_shadow_catcher = True
    link(plate)
    build_screw(m, 0.0, 0.0, angle=job.get("angle", 20.0))
    lighting(**job.get("light", {}))
    camera(-0.36, 0.36, -0.42, 0.30, job.get("ppi", 200))
    render(job["out"], samples=job.get("samples", 160))


JOBS = {"hero": job_hero, "preview": job_preview, "tile": job_tile, "frame": job_frame, "cover": job_cover, "screw": job_screw, "main": job_main}


def geometry():
    """Everything the card needs to place overlays, in inches."""
    return {
        "pitch": PITCH,
        "tile_w": OPEN_L + 2 * TILE_M,
        "tile_m": TILE_M,
        "slot_pad": SLOT_PAD,
        "overflow": OVERFLOW,
        "cap_h": CAP_H,
        "center_w": CENTER_W,
        "field_m": FIELD_M,
        "field_y": FIELD_Y,
        "frame_out": FRAME_OUT,
        "frame_slice": FRAME_SLICE,
        "cover_slice": COVER_SLICE,
        "chamfer": CHAMFER,
        "face_l": FACE_L,
        "cav": [CAV_D0, CAV_D1],
        "cav_x": CAV_X,
        "led": {"d": [2.652, 2.716], "x": [-0.066, 0.0]},
        "rating": {"d": 1.775, "x": 0.19, "cap": 0.076},
        "hero": {"body_w": BODY_W, "step_top": STEP_TOP, "step_bot": STEP_BOT, "pad": 0.08},
        "main": {"w": MAIN_W + 2 * MAIN_M, "h": MAIN_H + 2 * MAIN_M, "m": MAIN_M, "scale": MAIN_SCALE},
        "pivot_d": PIVOT_D,
        "body_w": BODY_W,
    }


def main():
    argv = sys.argv[sys.argv.index("--") + 1 :]
    if argv[0] == "--geometry":
        with open(argv[1], "w") as fh:
            json.dump(geometry(), fh, indent=1)
        return
    with open(argv[0]) as fh:
        jobs = json.load(fh)
    for job in jobs:
        JOBS[job["job"]](job)
        print("DONE", job["out"], flush=True)


if __name__ == "__main__":
    main()

#ifndef _EXPR_H__
#define _EXPR_H__

#include <memory>
#include <stdio.h>
#include <vector>
#include "VMState.h"

#define EXPR_UNDEFINED   -1
#define EXPR_Add		 7
#define EXPR_Sub		 8
#define EXPR_Mul		 9
#define EXPR_UDiv		 10
#define EXPR_SDiv		 11
#define EXPR_URem		 12
#define EXPR_SRem		 13
#define EXPR_Neg         14
#define EXPR_Not		 15
#define EXPR_And		 16
#define EXPR_Or		     17
#define EXPR_Xor		 18
#define EXPR_Shl		 19
#define EXPR_LShr		 20
#define EXPR_AShr		 21
#define EXPR_Equal		 22
#define EXPR_Distinct    23
#define EXPR_Ult		 24
#define EXPR_Ule		 25
#define EXPR_Ugt		 26
#define EXPR_Uge		 27
#define EXPR_Slt		 28
#define EXPR_Sle		 29
#define EXPR_Sgt		 30
#define EXPR_Sge		 31
#define EXPR_LOr		 32
#define EXPR_LAnd		 33
#define EXPR_LNot		 34

#define EXPR_SignEXT     35
#define EXPR_ZeroEXT     36
#define EXPR_Shrd        37

#define EXPR_Sign           38
#define EXPR_NoSign         39
#define EXPR_Overflow           40
#define EXPR_NoOverflow         41

#define EXPR_Combine        42
#define EXPR_Extract        43
#define EXPR_CombineMulti 44
#define EXPR_Bsr 45
#define EXPR_Bt 46
#define EXPR_Rotate 47

namespace EXPR {

class Expr {
    protected:

    // add the definition of different kinds of expression
    public:
    enum Kind {
        // the IDs follow the #define ones
        UNDEFINED = -1,

        // why no Const, Bin, ,Tri, and Ury?
        Const = 3,
        Bin,
        Tri,
        Ury,

        Add = 7,
        Sub,
        Mul,
        UDiv,

        SDiv, // 11
        URem,
        SRem,
        Neg,
        Not,
        And,
        Or,
        Xor,
        Shl,
        LShr,

        AShr, //21
        Equal,
        Distinct,
        Ult,
        Ule,
        Ugt,
        Uge,
        Slt,
        Sle,
        Sgt,

        Sge, //31
        Lor,
        LAnd,
        LNot,
        SignEXT,
        ZeroEXT,
        Shrd,
        Sign,
        NoSign,
        Overflow,

        NoOverflow, //41
        Combine,
        Extract,
        CombineMultiExpr,

        Bsr,
        Bt ,
        Rotate

    }; // end enum definition
    uint64_t val ;
    public:
        int exprID ;
        int size;
        int offset;

        Expr(int sz, int off=0) {
            this->size = sz, this->offset = off; this->exprID = -1 ;
        }
        Expr() {
            this->size = 4, this->offset = 0; this->exprID = -1 ;
        }
        ~Expr() {} ;
        bool Excute(int &size, long &val) {
            size = this->size ;
            val = 0 ;
            return true ;
        }

        virtual void print(void) {};
        
        //virtual void print(void) = 0;
        //
        // add a function to get Kind
        virtual Kind getKind() const = 0;
        int getExprSize() { return size; }
        void setExprSize(int sz) { size = sz; }
};

typedef std::shared_ptr<Expr> ExprPtr;

// User defined expression, usually be a user delcared symbolic object.
class UDefExpr : public Expr {
   protected:
    void *O;

   public:
    UDefExpr(void *obj) :Expr() {
        O = obj;
    }
    UDefExpr(void *obj, int sz, int off) : Expr(sz, off) {
        O = obj;
    }
    void print ();

    // add the implemenation of the virtual function
    Kind getKind() const { return UNDEFINED; }
    VMState::SYMemObject * getObject() { return (VMState::SYMemObject*) O; }
};

class ConstExpr : public Expr {
   protected:
    uint64_t V;

   public:
    ConstExpr(uint64_t value, int sz, int off) :Expr(sz, off) {
        V = value;
    }

    void print () ;

    // add the implemenation of the virtual function
    Kind getKind() const { return Const; }
    uint64_t getValue() { return V; }
    int getSize() {return size;}
};

class BinExpr : public Expr {
   // protected:
   public:
    ExprPtr R, L;
    
   public:
    ExprPtr getR() {return R;}
    ExprPtr getL() {return L;}

    BinExpr(ExprPtr r, ExprPtr l) : R(r), L(l), Expr(r->size, 0) {}
    BinExpr(ExprPtr r, ExprPtr l, int sz, int off) : Expr(sz, off), R(r), L(l) {}

   public:
    void print () ;

  
    Kind getKind() const { return Bin; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class AddExpr : public BinExpr {
   public:
    AddExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Add;}
    AddExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Add;}

  
    Kind getKind() const { return Add; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class SubExpr : public BinExpr {
   public:
    SubExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Sub;}
    SubExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Sub;}

  
    Kind getKind() const { return Sub; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class MulExpr : public BinExpr {
   public:
   // sz is source size.
    MulExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Mul;}
    MulExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Mul;}

  
    Kind getKind() const { return Mul; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class DivExpr : public BinExpr {
   public:
    DivExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_UDiv;}
    DivExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_UDiv;}

  
    Kind getKind() const { return UDiv; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class RemExpr : public BinExpr {
   public:
    RemExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_URem;}
    RemExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_URem;}
  
    Kind getKind() const { return URem; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class AndExpr : public BinExpr {
   public:
    AndExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_And;}
    AndExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_And;}

  
    Kind getKind() const { return And; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class OrExpr : public BinExpr {
   public:
    OrExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Or;}
    OrExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Or;}

  
    Kind getKind() const { return Or; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class XorExpr : public BinExpr {
   public:
    XorExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Xor;}
    XorExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Xor;}

  
    Kind getKind() const { return Xor; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class Shl_SalExpr : public BinExpr {
   public:
    Shl_SalExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Shl;}
    Shl_SalExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Shl;}

  
    Kind getKind() const { return Shl; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};
class ShrExpr : public BinExpr {
   public:
    ShrExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_LShr;}
    ShrExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_LShr;}

  
    Kind getKind() const { return LShr; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class SarExpr : public BinExpr {
   public:
    SarExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_AShr;}
    SarExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_AShr;}

  
    Kind getKind() const { return AShr; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class iDivExpr : public BinExpr {
   public:
    // r : Dividend, l : Divisor
    iDivExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_SDiv;}
    iDivExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_SDiv;}

  
    Kind getKind() const { return SDiv; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class iRemExpr : public BinExpr {
   public:
    iRemExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_SRem;}
    iRemExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_SRem;}

  
    Kind getKind() const { return SRem; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class UryExpr : public Expr {
   protected:
    ExprPtr E;
    UryExpr(ExprPtr e) : E(e), Expr(e->size, 0) {}
    UryExpr(ExprPtr e, int sz, int off) : Expr(sz, off), E(e) {}

   public:
    virtual void print () ;

  
    Kind getKind() const { return Ury; }
    ExprPtr getExprPtr() { return E; }

};

class NegExpr : public UryExpr {
   public:
    NegExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_Neg;}
    NegExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_Neg;}

  
    Kind getKind() const { return Neg; }
    ExprPtr getExprPtr() { return E; }
};

class NotExpr : public UryExpr {
   public:
    NotExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_Not;}
    NotExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_Not;}

  
    Kind getKind() const { return Not; }
    ExprPtr getExprPtr() { return E; }
};

class LNotExpr : public UryExpr {
   public:
    LNotExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_LNot;}
    LNotExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_LNot;}

  
    Kind getKind() const { return LNot; }
    ExprPtr getExprPtr() { return E; }
};

class SignExtExpr : public UryExpr {
   public:
    SignExtExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_SignEXT;}
    SignExtExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {
        exprID = EXPR_SignEXT;
        size = sz;
    }

  
    Kind getKind() const { return SignEXT; }
    ExprPtr getExprPtr() { return E; }
    int getSize() {return size;}
};

class ZeroExtExpr : public UryExpr {
   public:
    ZeroExtExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_ZeroEXT;}
    ZeroExtExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {
        exprID = EXPR_ZeroEXT;
        size = sz; //   return expected size after zero extension
    }

  
    Kind getKind() const { return ZeroEXT; }
    ExprPtr getExprPtr() { return E; }
    int getSize() {return size;}
};

class EqualExpr : public UryExpr {
    public:
        EqualExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_Equal;}
        EqualExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_Equal;}

  
    Kind getKind() const { return Equal; }
    ExprPtr getExprPtr() {return E; }
};

class DistinctExpr : public UryExpr {
    public:
        DistinctExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_Distinct;}
        DistinctExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_Distinct;}

  
    Kind getKind() const { return Distinct; }
    ExprPtr getExprPtr() { return E; }
};

class UltExpr : public BinExpr {
    public:
        UltExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Ult;}
        UltExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Ult;}

  
    Kind getKind() const { return Ult; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class UleExpr : public BinExpr {
    public:
        UleExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Ule;}
        UleExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Ule;}

  
    Kind getKind() const { return Ule; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class UgtExpr : public BinExpr {
    public:
        UgtExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Ugt;}
        UgtExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Ugt;}

  
    Kind getKind() const { return Ugt; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class UgeExpr : public BinExpr {
    public:
        UgeExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Uge;}
        UgeExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Uge;}

  
    Kind getKind() const { return Uge; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class SltExpr : public BinExpr {
    public:
        SltExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Slt;}
        SltExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Slt;}

  
    Kind getKind() const { return Slt; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class SleExpr : public BinExpr {
    public:
        SleExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Sle;}
        SleExpr(ExprPtr r, ExprPtr l,  int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Sle;}

  
    Kind getKind() const { return Sle; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};

class SgtExpr : public BinExpr {
    public:
        SgtExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Sgt;}
        SgtExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Sgt;}

  
    Kind getKind() const { return Sgt; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
} ;

class SgeExpr : public BinExpr {
    public:
        SgeExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Sge;}
        SgeExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Sge;}

  
    Kind getKind() const { return Sge; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
} ;

class SignExpr : public UryExpr {
    public:
        SignExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_Sign;}
        SignExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_Sign;}

  
    Kind getKind() const { return Sign; }
    ExprPtr getExprPtr() { return E; }
    int getSize() {return size;}
} ;

class NoSignExpr : public UryExpr {
    public:
        NoSignExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_NoSign;}
        NoSignExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_NoSign;}

  
    Kind getKind() const { return NoSign; }
    ExprPtr getExprPtr() { return E; }
    int getSize() {return size;}
} ;
class OverflowExpr : public UryExpr {
    public:
        OverflowExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_Overflow;}
        OverflowExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_Overflow;}

  
    Kind getKind() const { return Overflow;}
    ExprPtr getExprPtr() { return E; }
} ;
class NoOverflowExpr : public UryExpr {
    public:
        NoOverflowExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_NoOverflow;}
        NoOverflowExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_NoOverflow;}

  
    Kind getKind() const { return NoOverflow; }
    ExprPtr getExprPtr() { return E; }
} ;

class TriExpr : public Expr {
   protected:
    ExprPtr R, M, L;

    TriExpr(ExprPtr r, ExprPtr m, ExprPtr l) : R(r), M(m), L(l) {}
    TriExpr(ExprPtr r, ExprPtr m, ExprPtr l, int sz, int off) : Expr(sz, off), R(r), M(m), L(l) {}

    void print () ;

  
    Kind getKind() const { return Tri; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrM() { return M; }
    ExprPtr getExprPtrL() { return L; }
};

class ShrdExpr :public TriExpr {
    public:
    ShrdExpr(ExprPtr r, ExprPtr m, ExprPtr l) :TriExpr(r, m, l, r->size, 0) {exprID = EXPR_Shrd;}
    ShrdExpr(ExprPtr r, ExprPtr m, ExprPtr l, int sz, int off) : TriExpr(r, m, l, sz, off) {exprID = EXPR_Shrd;}

  
    Kind getKind() const { return Shrd; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrM() { return M; }
    ExprPtr getExprPtrL() { return L; }
};

class CombineExpr :public BinExpr {
    public:
    int rsz, lsz ;
    // r is high bytes, l is low bytes.
    CombineExpr(ExprPtr r, ExprPtr l, int rsize, int lsize, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Combine;rsz=rsize; lsz=lsize;}

  
    Kind getKind() const { return Combine; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
};
class ExtractExpr : public UryExpr {
    public:
        int s, e;
        ExtractExpr(ExprPtr expr, int start, int end) : UryExpr(expr, end-start, 0) {exprID = EXPR_Extract;s=start; e=end;}
        ExtractExpr(ExprPtr expr, int start, int end, int sz, int off) : UryExpr(expr, sz, off) {exprID = EXPR_Extract;s=start; e=end;}

        virtual void print () ;

  
    Kind getKind() const { return Extract; }
    ExprPtr getExprPtr() {return E; }
    int getStart(){ return s; }
    int getEnd(){ return e; }
} ;

class CombineMultiExpr :public Expr {
    public:
    std::vector <int> offsets ;
    std::vector <int> sizes ;
    std::vector <ExprPtr> exprs ;
    // r is high bytes, l is low bytes.

    CombineMultiExpr(std::vector <ExprPtr> e, std::vector <int> o, std::vector <int> s) :Expr()
        {exprID = EXPR_CombineMulti; exprs=e; offsets=o; sizes=s;} ;

    CombineMultiExpr(std::vector <ExprPtr> e, std::vector <int> o, std::vector <int> s, int sz, int off) : Expr(sz, off)
        {exprID = EXPR_CombineMulti; exprs=e; offsets=o; sizes=s;}

    virtual void print () ;

    //  
    Kind getKind() const { return Kind::CombineMultiExpr; }
    std::vector<ExprPtr> getMultiExprPtr()  { return exprs; }
    std::vector<int> getMultiSize() { return sizes; }
};

class BsrExpr : public UryExpr {
   public:
    BsrExpr(ExprPtr e) : UryExpr(e) {exprID = EXPR_Bsr;}
    BsrExpr(ExprPtr e, int sz, int off) : UryExpr(e, sz, off) {exprID = EXPR_Bsr;}

  
    Kind getKind() const { return Kind::Bsr; }
    ExprPtr getExprPtr() { return E; }
};

class BtExpr : public BinExpr {
    public:
        BtExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Bt;}
        BtExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Bt;}

  
    Kind getKind() const { return Kind::Bt; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
} ;

class RotateExpr : public BinExpr {
    public:
        RotateExpr(ExprPtr r, ExprPtr l) : BinExpr(r, l) {exprID = EXPR_Rotate;}
        RotateExpr(ExprPtr r, ExprPtr l, int sz, int off) : BinExpr(r, l, sz, off) {exprID = EXPR_Rotate;}

  
    Kind getKind() const { return Kind::Rotate; }
    ExprPtr getExprPtrR() { return R; }
    ExprPtr getExprPtrL() { return L; }
} ;
};  // namespace EXPR

#endif  // _EXPR_H__
